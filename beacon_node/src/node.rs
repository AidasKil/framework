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
    types::{Attestation, Checkpoint, SignedBeaconBlock},
};

pub struct Node<C: Config>(Store<C>);

impl<C: Config> Node<C> {
    pub fn new(genesis_state: BeaconState<C>) -> Self {
        // The way the genesis block is constructed makes it possible for many parties to
        // independently produce the same block. But why does the genesis block have to
        // exist at all? Perhaps the first block could be proposed by a validator as well
        // (and not necessarily in slot 0)?
        let mut genesis_block = SignedBeaconBlock::default();
        // Note that `genesis_block.message.body.eth1_data` is not set to
        // `genesis_state.latest_eth1_data`.
        genesis_block.message.state_root = crypto::hash_tree_root(&genesis_state);
        Self(Store::new(genesis_state, genesis_block))
    }

    pub fn head_state(&self) -> &BeaconState<C> {
        self.0.head_state()
    }

    pub fn handle_slot_start(&mut self, slot: Slot) -> Result<()> {
        info!("slot {} started", slot);
        self.0.on_slot(slot)
    }

    pub fn handle_slot_midpoint(&mut self, slot: Slot) {
        info!("slot {} midpoint", slot);
    }
}

impl<C: Config> Networked<C> for Node<C> {
    fn accept_beacon_block(&mut self, block: SignedBeaconBlock<C>) -> Result<()> {
        info!("received beacon block: {:?}", block);
        self.0.on_block(block)
    }

    fn accept_beacon_attestation(&mut self, attestation: Attestation<C>) -> Result<()> {
        info!("received beacon attestation: {:?}", attestation);
        self.0.on_attestation(attestation)
    }

    fn get_status(&self) -> Status {
        let head_state = self.0.head_state();
        let Checkpoint { epoch, root } = head_state.finalized_checkpoint;
        Status {
            fork_version: head_state.fork.current_version,
            finalized_root: root,
            finalized_epoch: epoch,
            head_root: crypto::hash_tree_root(head_state),
            head_slot: head_state.slot,
        }
    }

    fn get_beacon_block(&self, root: H256) -> Option<&SignedBeaconBlock<C>> {
        self.0.block(root)
    }
}

// There used to be tests here but we were forced to omit them to save time.
