//! Traits for abstracting over different Ethereum 2.0 network protocols.
//!
//! Currently only [`BeaconBlock`]s and beacon [`Attestation`]s can be gossiped, because those are
//! the only types of objects supported by Hobbits. Methods for [other types of objects] will be
//! added later.
//!
//! [`Attestation`]: types::types::Attestation
//! [`BeaconBlock`]: types::types::BeaconBlock
//!
//! [other types of objects]: https://github.com/ethereum/eth2.0-specs/blob/1f3a5b156f7a0e7616f7c8bc31e27fa4da392139/specs/networking/p2p-interface.md#message

use anyhow::Result;
use types::{
    config::Config,
    primitives::{Epoch, Slot, Version, H256},
    types::{Attestation, SignedBeaconBlock},
};

#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub fork_version: Version,
    pub finalized_root: H256,
    pub finalized_epoch: Epoch,
    pub head_root: H256,
    pub head_slot: Slot,
}

pub trait Network<C: Config> {
    fn publish_beacon_block(&self, beacon_block: SignedBeaconBlock<C>) -> Result<()>;

    fn publish_beacon_attestation(&self, attestation: Attestation<C>) -> Result<()>;
}

pub trait Networked<C: Config>: 'static {
    fn accept_beacon_block(&mut self, beacon_block: SignedBeaconBlock<C>) -> Result<()>;

    fn accept_beacon_attestation(&mut self, attestation: Attestation<C>) -> Result<()>;

    fn get_status(&self) -> Status;

    fn get_beacon_block(&self, root: H256) -> Option<&SignedBeaconBlock<C>>;
}
