//! A [`Stream`] that produces beacon chain slots.
//!
//! # Implementation
//!
//! This is implemented using [`Interval`]. Some subtleties to keep in mind:
//!
//! - The API of [`Interval`] (as well as other timer utilities in [`tokio::timer`]) uses
//!   [`Instant`]s. [`Instant`]s are opaque. There is no way to directly convert a timestamp
//!   (of any kind, not just Unix time) to an [`Instant`]. The hack in [`start`] may result in
//!   unexpected behavior in extreme conditions.
//!
//! - An [`Interval`] may produce items late, but the delays do not accumulate. The interval of time
//!   between consecutive items produced by [`Interval`] may be shorter than the [`Duration`] passed
//!   to [`Interval::new`].
//!
//!   However, this only applies if the items are processed quickly enough. If a consumer takes more
//!   than [`Config::SecondsPerSlot`] seconds to process a single item, all subsequent slots will be
//!   delayed. In other words, [`Interval`] only produces one item at a time.
//!
//! - It is unclear how [`Interval`] behaves around leap seconds.
//!
//! - An [`Interval`] may fail with an [`Error::at_capacity`] error. [`Error::at_capacity`] errors
//!   are transient, but we do not try to recover from them. They are not likely to happen.
//!
//! # Possible alternatives
//!
//! There are several other crates we could choose from:
//! - [`clokwerk`]
//! - [`job_scheduler`]
//! - [`schedule`]
//! - [`timer`]
//! - [`white_rabbit`]
//!
//! The first 3 do not come with any timers or runtimes. They need to be driven manually:
//! ```ignore
//! loop {
//!     scheduler.run_pending();
//!     thread::sleep(duration);
//! }
//! ```
//! This has some benefits:
//! - By varying the sleep duration, we can trade higher CPU usage for higher precision.
//! - Leap seconds should be handled correctly without any extra effort on our part.
//!
//! [`timer`] and [`white_rabbit`] use timers internally.
//! They are likely to be more efficient, but it is unclear if they handle leap seconds correctly.
//!
//! None of these libraries are designed to work with [`futures`](https://crates.io/crates/futures),
//! but making them work together should be as simple as using a channel.
//!
//! [`Duration`]: core::time::Duration
//! [`Instant`]:  std::time::Instant
//!
//! [`Config::SecondsPerSlot`]: types::config::Config::SecondsPerSlot
//! [`Error::at_capacity`]:     tokio::timer::Error::at_capacity
//! [`Interval::new`]:          tokio::timer::Interval::new
//! [`Interval`]:               tokio::timer::Interval
//! [`Stream`]:                 futures::Stream
//!
//! [`start`]: crate::slot_timer::start
//!
//! [`clokwerk`]:      https://crates.io/crates/clokwerk
//! [`job_scheduler`]: https://crates.io/crates/job_scheduler
//! [`schedule`]:      https://crates.io/crates/schedule
//! [`timer`]:         https://crates.io/crates/timer
//! [`white_rabbit`]:  https://crates.io/crates/white_rabbit

use core::{iter, mem, time::Duration};
use std::time::{Instant, SystemTime};

use anyhow::{Error, Result};
use futures::{stream, Stream};
use tokio::timer::Interval;
use typenum::Unsigned as _;
use types::{
    config::Config,
    consts::GENESIS_SLOT,
    primitives::{Slot, UnixSeconds},
};

use crate::fake_time::{InstantLike, SystemTimeLike};

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum Tick {
    SlotStart(Slot),
    SlotMidpoint(Slot),
}

impl Tick {
    fn stream<E>(mut self) -> impl Stream<Item = Self, Error = E> {
        stream::iter_ok(iter::repeat_with(move || {
            let next = self.next();
            mem::replace(&mut self, next)
        }))
    }

    fn next(self) -> Self {
        match self {
            Self::SlotStart(slot) => Self::SlotMidpoint(slot),
            // This will overflow in the far future.
            Self::SlotMidpoint(slot) => Self::SlotStart(slot + 1),
        }
    }
}

pub fn start<C: Config>(
    genesis_unix_time: UnixSeconds,
) -> Result<impl Stream<Item = Tick, Error = Error>> {
    // We assume the `Instant` and `SystemTime` obtained here correspond to the same point in time.
    // This is slightly inaccurate but the error will probably be negligible compared to clock
    // differences between different nodes in the network.
    let (next_tick, instant) =
        next_tick_with_instant::<C, _, _>(Instant::now(), SystemTime::now(), genesis_unix_time)?;

    let half_slot_duration = Duration::from_secs(C::SecondsPerSlot::U64) / 2;

    let slot_stream = Interval::new(instant, half_slot_duration)
        .zip(next_tick.stream())
        .map(|(_, tick)| tick)
        .from_err();

    Ok(slot_stream)
}

fn next_tick_with_instant<C: Config, I: InstantLike, S: SystemTimeLike>(
    now_instant: I,
    now_system_time: S,
    genesis_unix_time: UnixSeconds,
) -> Result<(Tick, I)> {
    // The specification does not make it clear whether the number of the first slot after genesis
    // is 0 or 1. The fork choice rule fails if the slot is the same as in the genesis block, so we
    // assume the first slot is supposed to be 1.
    let first_slot = GENESIS_SLOT + 1;

    let unix_epoch_to_now = now_system_time.duration_since(S::UNIX_EPOCH)?;
    let unix_epoch_to_genesis = Duration::from_secs(genesis_unix_time);

    // Some platforms do not support negative `Instant`s. Operations that would produce an `Instant`
    // corresponding to time before the epoch will panic on those platforms. The epoch in question
    // is not the Unix epoch but a platform dependent value, typically the system boot time.
    // This means we are not allowed to subtract `Duration`s from `Instant`s. The `InstantLike`
    // trait conveniently prevents us from doing so.

    let next_tick;
    let now_to_next_tick;

    if unix_epoch_to_now <= unix_epoch_to_genesis {
        next_tick = Tick::SlotStart(first_slot);
        now_to_next_tick = unix_epoch_to_genesis - unix_epoch_to_now;
    } else {
        let genesis_to_now = unix_epoch_to_now - unix_epoch_to_genesis;
        // The `NonZero` bound on `Config::SecondsPerSlot` ensures this will not fail at runtime.
        let slot_offset = genesis_to_now.as_secs() / C::SecondsPerSlot::U64;
        let genesis_to_current_slot = Duration::from_secs(slot_offset * C::SecondsPerSlot::U64);
        let current_slot_to_now = genesis_to_now - genesis_to_current_slot;

        let slot_duration = Duration::from_secs(C::SecondsPerSlot::U64);
        let half_slot_duration = slot_duration / 2;
        let zero_duration = Duration::from_secs(0);

        if current_slot_to_now == zero_duration {
            next_tick = Tick::SlotStart(first_slot + slot_offset);
            now_to_next_tick = zero_duration;
        } else if current_slot_to_now <= half_slot_duration {
            next_tick = Tick::SlotMidpoint(first_slot + slot_offset);
            now_to_next_tick = half_slot_duration - current_slot_to_now;
        } else {
            next_tick = Tick::SlotStart(first_slot + slot_offset + 1);
            now_to_next_tick = slot_duration - current_slot_to_now;
        }
    };

    Ok((next_tick, now_instant + now_to_next_tick))
}

#[cfg(test)]
mod tests {
    use std::thread;

    use futures::{future, sync::mpsc, Async, Future as _};
    use test_case::test_case;
    use tokio::runtime::Builder;
    use types::config::MinimalConfig;
    use void::ResultVoidExt as _;

    use crate::fake_time::{FakeInstant, FakeSystemTime, Timespec};

    use super::*;

    #[test]
    fn tick_stream_produces_consecutive_ticks_starting_with_self() {
        let mut stream = Tick::SlotStart(0).stream().wait().map(Result::void_unwrap);

        assert_eq!(stream.next(), Some(Tick::SlotStart(0)));
        assert_eq!(stream.next(), Some(Tick::SlotMidpoint(0)));
        assert_eq!(stream.next(), Some(Tick::SlotStart(1)));
        assert_eq!(stream.next(), Some(Tick::SlotMidpoint(1)));
        assert_eq!(stream.next(), Some(Tick::SlotStart(2)));
        assert_eq!(stream.next(), Some(Tick::SlotMidpoint(2)));
    }

    #[test]
    fn new_produces_slots_every_6_seconds() -> Result<()> {
        let now_unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        let genesis_unix_time = now_unix_time + 1;

        let runtime = Builder::new().name_prefix("timer-test-").build()?;
        let tick_stream = start::<MinimalConfig>(genesis_unix_time)?;
        let mut spawned_tick_stream = mpsc::spawn(tick_stream, &runtime.executor(), 0);

        let mut assert_poll = |expected_async| {
            future::ok(())
                .and_then(|()| spawned_tick_stream.poll())
                .inspect(|actual_async| assert_eq!(actual_async, &expected_async))
                .wait()
        };
        let sleep = |seconds| thread::sleep(Duration::from_secs(seconds));

        assert_poll(Async::NotReady)?;
        sleep(1);
        assert_poll(Async::Ready(Some(Tick::SlotStart(1))))?;
        sleep(2);
        assert_poll(Async::NotReady)?;
        sleep(1);
        assert_poll(Async::Ready(Some(Tick::SlotMidpoint(1))))?;
        sleep(2);
        assert_poll(Async::NotReady)?;
        sleep(1);
        assert_poll(Async::Ready(Some(Tick::SlotStart(2))))?;

        Ok(())
    }

    #[test_case(100, Tick::SlotStart(1),    777; "0th slot start before genesis")]
    #[test_case(777, Tick::SlotStart(1),    777; "0th slot start at genesis")]
    #[test_case(778, Tick::SlotMidpoint(1), 780; "0th slot midpoint 1 second after genesis")]
    #[test_case(780, Tick::SlotMidpoint(1), 780; "0th slot midpoint 3 seconds after genesis")]
    #[test_case(781, Tick::SlotStart(2),    783; "1st slot start 4 seconds after genesis")]
    #[test_case(783, Tick::SlotStart(2),    783; "1st slot start 6 seconds after genesis")]
    #[test_case(784, Tick::SlotMidpoint(2), 786; "1st slot midpoint 7 seconds after genesis")]
    fn next_tick_with_instant_produces(
        now: UnixSeconds,
        expected_tick: Tick,
        expected_timestamp: UnixSeconds,
    ) {
        let now_timespec = Timespec::from_secs(now);
        let expected_instant = FakeInstant(Timespec::from_secs(expected_timestamp));

        let (actual_tick, actual_instant) = next_tick_with_instant::<MinimalConfig, _, _>(
            FakeInstant(now_timespec),
            FakeSystemTime(now_timespec),
            777,
        )
        .expect("FakeSystemTime cannot represent times before the Unix epoch");

        assert_eq!(actual_tick, expected_tick);
        assert_eq!(actual_instant, expected_instant);
    }
}
