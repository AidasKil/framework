// This module currently does very little. In the future it is intended to have other
// responsibilities, such as accumulating unprocessed deposits, proposing beacon blocks, and
// creating beacon attestations.

use anyhow::Result;
use beacon_fork_choice::Store;
use eth2_network::{Networked, Status};
use helper_functions::crypto;
use log::info;
use types::{
    beacon_state::BeaconState,
    config::Config,
    primitives::{Slot, H256},
    types::{Attestation, Eth1Data, SignedBeaconBlock},
};

use crate::genesis;

pub struct Node<C: Config> {
    store: Store<C>,
    eth1_data: Eth1Data,
}

impl<C: Config> Node<C> {
    pub fn new(genesis_state: BeaconState<C>) -> Self {
        let genesis_block = genesis::block(&genesis_state);
        let eth1_data = genesis_state.eth1_data.clone();
        Self {
            store: Store::new(genesis_state, genesis_block),
            eth1_data,
        }
    }

    pub fn head_state(&self) -> Result<&BeaconState<C>> {
        self.store.head_state()
    }

    pub fn handle_eth1_data(&mut self, eth1_data: Eth1Data) {
        info!("received Ethereum 1.0 data: {:?}", eth1_data);
        self.eth1_data = eth1_data;
    }

    pub fn handle_slot_start(&mut self, slot: Slot) -> Result<()> {
        info!("slot {} started", slot);
        self.store.on_slot(slot)
    }
}

impl<C: Config> Networked<C> for Node<C> {
    fn accept_beacon_block(&mut self, block: SignedBeaconBlock<C>) -> Result<()> {
        info!("received beacon block: {:?}", block);
        self.store.on_block(block)
    }

    fn accept_beacon_attestation(&mut self, attestation: Attestation<C>) -> Result<()> {
        info!("received beacon attestation: {:?}", attestation);
        self.store.on_attestation(attestation)
    }

    fn get_status(&self) -> Result<Status> {
        let head_state = self.store.head_state()?;
        let status = Status {
            fork_version: head_state.fork.current_version,
            finalized_root: head_state.finalized_checkpoint.root,
            finalized_epoch: head_state.finalized_checkpoint.epoch,
            head_root: crypto::hash_tree_root(head_state),
            head_slot: head_state.slot,
        };
        Ok(status)
    }

    fn get_beacon_block(&self, root: H256) -> Option<&SignedBeaconBlock<C>> {
        self.store.block(root)
    }
}

// There used to be tests here but we were forced to omit them to save time.
