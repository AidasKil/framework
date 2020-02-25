use std::{env, fs::File, process};

use anyhow::Result;
use eth2_network_libp2p::Qutex;
use futures::{Future as _, Stream as _};
use log::{error, Level};
use serde::de::DeserializeOwned;
use tokio::runtime::current_thread;
use types::config::{Config, MainnetConfig, MinimalConfig};

use crate::{
    node::Node,
    runtime_config::{Preset, RuntimeConfig},
    slot_timer::Tick,
};

mod fake_time;
mod node;
mod runtime_config;
mod slot_timer;

fn main() {
    simple_logger::init_with_level(Level::Info).expect("logger was already initialized");
    if let Err(error) = parse_args_and_run_node() {
        error!("{}", error);
        process::exit(1);
    }
}

fn parse_args_and_run_node() -> Result<()> {
    // `<Args as Iterator>::next` will panic if any of the arguments are not valid `String`s.
    let config = RuntimeConfig::parse(env::args())?;
    match config.preset {
        Preset::Mainnet => run_node::<MainnetConfig>(config),
        Preset::Minimal => run_node::<MinimalConfig>(config),
    }
}

fn run_node<C: Config + DeserializeOwned>(config: RuntimeConfig) -> Result<()> {
    let genesis_state_file = File::open(config.genesis_state_path)?;
    let genesis_state = serde_yaml::from_reader(genesis_state_file)?;

    let node = Node::new(genesis_state);

    let tick_stream = slot_timer::start::<C>(node.head_state().genesis_time)?;

    // In previous versions, `Node` would consume an `Iterator` of inputs and produce an `Iterator`
    // of outputs. This approach required no explicit synchronization, but made abstracting over
    // different network protocols difficult.
    //
    // The current version of `Node` is written in a more object-oriented style and instead exposes
    // methods that take mutable references. These methods are called from multiple tasks, each of
    // which processes a stream of inputs of a distinct type. We use `Qutex` for safe concurrent
    // access to the `Node` (`Mutex` is not compatible with `futures`).
    //
    // Scoped threads seemed like they would useful for this, but they turned out to not be
    // sufficient. If an error occurs in one of the tasks, we want them all to stop processing the
    // streams and shut down in a controlled manner. This would be hard to do if we processed the
    // streams synchronously. We can achieve the desired outcome with `futures`, at the cost of
    // rewriting some code in asynchronous style.
    let qutex = Qutex::new(node);

    let (_, receiver) = eth2_network_libp2p::channel::<C>();
    let run_network = eth2_network_libp2p::run_network(&config.network, qutex.clone(), receiver)?;

    let handle_ticks = tick_stream.for_each(|tick| {
        qutex.clone().lock().from_err().and_then(move |mut node| {
            match tick {
                Tick::SlotStart(slot) => node.handle_slot_start(slot)?,
                Tick::SlotMidpoint(slot) => node.handle_slot_midpoint(slot),
            }
            Ok(())
        })
    });

    // Tokio timers fail when polled outside a task, so we need to start a Tokio runtime.
    // The single threaded runtime (`current_thread`) is enough as long as we do not use
    // `Future::wait`. `Future::wait` appears to park the thread indefinitely.
    current_thread::block_on_all(run_network.join(handle_ticks).map(|_| ()))
}
