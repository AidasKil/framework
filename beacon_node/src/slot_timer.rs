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

use core::time::Duration;
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
pub enum Responsibility {
    Propose,
    Attest,
    Aggregate,
}

impl Responsibility {
    pub fn is_slot_start(self) -> bool {
        match self {
            Self::Propose => true,
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Tick(pub Slot, pub Responsibility);

impl Tick {
    fn into_iter(mut self) -> impl Iterator<Item = Self> {
        core::iter::repeat_with(move || {
            let next = self.next();
            core::mem::replace(&mut self, next)
        })
    }

    fn next(self) -> Self {
        match self {
            Self(slot, Responsibility::Propose) => Self(slot, Responsibility::Attest),
            Self(slot, Responsibility::Attest) => Self(slot, Responsibility::Aggregate),
            // This will overflow in the far future.
            Self(slot, Responsibility::Aggregate) => Self(slot + 1, Responsibility::Propose),
        }
    }
}

pub fn start<C: Config>(
    genesis_unix_time: UnixSeconds,
) -> Result<impl Stream<Item = Tick, Error = Error>> {
    // We assume the `Instant` and `SystemTime` obtained here correspond to the same point in time.
    // This is slightly inaccurate but the error will probably be negligible compared to clock
    // differences between different nodes in the network.
    let (next_tick, next_instant) =
        next_tick_with_instant::<C, _, _>(Instant::now(), SystemTime::now(), genesis_unix_time)?;

    let third_of_slot = Duration::from_secs(C::ThirdOfSlot::U64);

    let slot_stream = Interval::new(next_instant, third_of_slot)
        .zip(stream::iter_ok(next_tick.into_iter()))
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

    let mut next_tick;
    let mut now_to_next_tick;

    if unix_epoch_to_now <= unix_epoch_to_genesis {
        next_tick = Tick(first_slot, Responsibility::Propose);
        now_to_next_tick = unix_epoch_to_genesis - unix_epoch_to_now;
    } else {
        let third_of_slot = Duration::from_secs(C::ThirdOfSlot::U64);
        let seconds_per_slot = C::ThirdOfSlot::U64 * 3;
        let genesis_to_now = unix_epoch_to_now - unix_epoch_to_genesis;
        // The `NonZero` bound on `Config::ThirdOfSlot` ensures this will not fail at runtime.
        let slot_offset = genesis_to_now.as_secs() / seconds_per_slot;
        let genesis_to_current_slot = Duration::from_secs(slot_offset * seconds_per_slot);
        let current_slot_to_now = genesis_to_now - genesis_to_current_slot;

        next_tick = Tick(first_slot + slot_offset, Responsibility::Propose);
        now_to_next_tick = Duration::from_secs(0);

        while now_to_next_tick < current_slot_to_now {
            next_tick = next_tick.next();
            now_to_next_tick += third_of_slot;
        }

        now_to_next_tick -= current_slot_to_now;
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

    use crate::fake_time::{FakeInstant, FakeSystemTime, Timespec};

    use super::*;

    #[test]
    fn tick_into_iter_produces_consecutive_ticks_starting_with_self() {
        let actual = Tick(0, Responsibility::Propose)
            .into_iter()
            .take(9)
            .collect::<Vec<_>>();

        let expected = [
            Tick(0, Responsibility::Propose),
            Tick(0, Responsibility::Attest),
            Tick(0, Responsibility::Aggregate),
            Tick(1, Responsibility::Propose),
            Tick(1, Responsibility::Attest),
            Tick(1, Responsibility::Aggregate),
            Tick(2, Responsibility::Propose),
            Tick(2, Responsibility::Attest),
            Tick(2, Responsibility::Aggregate),
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn new_produces_ticks_every_2_seconds() -> Result<()> {
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
        let wait_a_second = || thread::sleep(Duration::from_secs(1));

        assert_poll(Async::NotReady)?;
        wait_a_second();
        assert_poll(Async::Ready(Some(Tick(1, Responsibility::Propose))))?;
        wait_a_second();
        assert_poll(Async::NotReady)?;
        wait_a_second();
        assert_poll(Async::Ready(Some(Tick(1, Responsibility::Attest))))?;
        wait_a_second();
        assert_poll(Async::NotReady)?;
        wait_a_second();
        assert_poll(Async::Ready(Some(Tick(1, Responsibility::Aggregate))))?;
        wait_a_second();
        assert_poll(Async::NotReady)?;
        wait_a_second();
        assert_poll(Async::Ready(Some(Tick(2, Responsibility::Propose))))?;

        Ok(())
    }

    #[test_case(100, 777, Tick(1, Responsibility::Propose))]
    #[test_case(777, 777, Tick(1, Responsibility::Propose))]
    #[test_case(778, 779, Tick(1, Responsibility::Attest))]
    #[test_case(779, 779, Tick(1, Responsibility::Attest))]
    #[test_case(780, 781, Tick(1, Responsibility::Aggregate))]
    #[test_case(781, 781, Tick(1, Responsibility::Aggregate))]
    #[test_case(782, 783, Tick(2, Responsibility::Propose))]
    #[test_case(783, 783, Tick(2, Responsibility::Propose))]
    fn next_tick_with_instant_produces(
        now_seconds: UnixSeconds,
        expected_seconds: UnixSeconds,
        expected_tick: Tick,
    ) {
        let now_timespec = Timespec::from_secs(now_seconds);
        let expected_instant = FakeInstant(Timespec::from_secs(expected_seconds));

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
