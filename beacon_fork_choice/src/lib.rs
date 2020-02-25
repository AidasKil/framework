//! Based on the naive LMD-GHOST fork choice rule implementation in the specification:
//! <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md>
//!
//! `assert`s from Python are represented by statements that either delay the processing of the
//! offending object or return `Err`. All other operations that can raise exceptions in Python
//! (like indexing into `dict`s) are represented by statements that panic on failure.

use core::{convert::TryInto as _, mem};
use std::collections::{BTreeMap, HashMap};

use anyhow::{ensure, Result};
use error_utils::DebugAsError;
use helper_functions::{beacon_state_accessors, crypto, misc, predicates};
use log::info;
use maplit::{btreemap, hashmap};
use thiserror::Error;
use transition_functions::process_slot;
use types::{
    config::Config,
    consts::GENESIS_EPOCH,
    primitives::{Epoch, Gwei, Slot, ValidatorIndex, H256},
    types::{Attestation, BeaconBlock, Checkpoint, SignedBeaconBlock},
    BeaconState,
};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Error)]
enum Error<C: Config> {
    #[error("slot {new_slot} is not later than {old_slot}")]
    SlotNotLater { old_slot: Slot, new_slot: Slot },
    #[error("block is not a descendant of finalized block (block: {block:?}, finalized_block: {finalized_block:?})")]
    BlockNotDescendantOfFinalized {
        block: SignedBeaconBlock<C>,
        finalized_block: SignedBeaconBlock<C>,
    },
    #[error(
        "attestation votes for a checkpoint in the wrong epoch (attestation: {attestation:?})"
    )]
    AttestationTargetsWrongEpoch { attestation: Attestation<C> },
    #[error("attestation votes for a block from the future (attestation: {attestation:?}, block: {block:?})")]
    AttestationForFutureBlock {
        attestation: Attestation<C>,
        block: SignedBeaconBlock<C>,
    },
}

/// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#latestmessage>
type LatestMessage = Checkpoint;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum DelayedObject<C: Config> {
    Block(SignedBeaconBlock<C>),
    Attestation(Attestation<C>),
}

/// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#store>
pub struct Store<C: Config> {
    slot: Slot,
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    best_justified_checkpoint: Checkpoint,
    // We store `SignedBeaconBlock`s instead of `BeaconBlockHeader`s because we need to return them
    // to the network stack in response to queries. Also, signatures may be required in the future
    // to implement slashing.
    blocks: HashMap<H256, SignedBeaconBlock<C>>,
    // `blocks` and `block_states` could be combined into a single map.
    // We've left them separate to match the specification more closely.
    block_states: HashMap<H256, BeaconState<C>>,
    checkpoint_states: HashMap<Checkpoint, BeaconState<C>>,
    latest_messages: HashMap<ValidatorIndex, LatestMessage>,

    // Extra fields used for delaying and retrying objects.
    delayed_until_block: HashMap<H256, Vec<DelayedObject<C>>>,
    delayed_until_slot: BTreeMap<Slot, Vec<DelayedObject<C>>>,
}

impl<C: Config> Store<C> {
    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#get_forkchoice_store>
    pub fn new(anchor_state: BeaconState<C>, anchor_block: SignedBeaconBlock<C>) -> Self {
        let epoch = beacon_state_accessors::get_current_epoch(&anchor_state);
        let root = crypto::hash_tree_root(&anchor_block.message);
        let checkpoint = Checkpoint { epoch, root };

        Self {
            slot: anchor_state.slot,
            justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            best_justified_checkpoint: checkpoint,
            blocks: hashmap! {root => anchor_block},
            block_states: hashmap! {root => anchor_state.clone()},
            checkpoint_states: hashmap! {checkpoint => anchor_state},
            latest_messages: hashmap! {},

            delayed_until_slot: btreemap! {},
            delayed_until_block: hashmap! {},
        }
    }

    pub fn head_state(&self) -> &BeaconState<C> {
        &self.block_states[&self.head()]
    }

    pub fn block(&self, root: H256) -> Option<&SignedBeaconBlock<C>> {
        self.blocks.get(&root)
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#on_tick>
    ///
    /// Unlike `on_tick` in the specification, this should be called at the start of a slot instead
    /// of every second. The fork choice rule doesn't need a precise timestamp.
    pub fn on_slot(&mut self, slot: Slot) -> Result<()> {
        ensure!(
            self.slot < slot,
            Error::<C>::SlotNotLater {
                old_slot: self.slot,
                new_slot: slot
            },
        );

        // > update store time
        self.slot = slot;

        // > Not a new epoch, return
        // > Update store.justified_checkpoint if a better checkpoint is known
        if self.slots_since_epoch_start() == 0
            && self.justified_checkpoint.epoch < self.best_justified_checkpoint.epoch
        {
            self.justified_checkpoint = self.best_justified_checkpoint;
        }

        self.retry_delayed_until_slot(slot)
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#on_block>
    pub fn on_block(&mut self, signed_block: SignedBeaconBlock<C>) -> Result<()> {
        let block = &signed_block.message;

        let mut finalized_slot = Self::start_of_epoch(self.finalized_checkpoint.epoch);

        // Ignore blocks from slots not later than the finalized block. Doing so ensures that:
        // - The genesis block is accepted even though it does not represent a state transition.
        // - Blocks that are already known and are received again are always accepted.
        if block.slot <= finalized_slot {
            return Ok(());
        }

        let pre_state = if let Some(state) = self.block_states.get(&block.parent_root) {
            state
        } else {
            self.delay_until_block(block.parent_root, DelayedObject::Block(signed_block));
            return Ok(());
        };

        // > Blocks cannot be in the future.
        // > If they are, their consideration must be delayed until the are in the past.
        if self.slot < block.slot {
            self.delay_until_slot(block.slot, DelayedObject::Block(signed_block));
            return Ok(());
        }

        let block_root = crypto::hash_tree_root(block);

        // > Check block is a descendant of the finalized block at the checkpoint finalized slot
        ensure!(
            self.ancestor_without_lookup(block_root, &signed_block.message, finalized_slot)
                == self.finalized_checkpoint.root,
            Error::BlockNotDescendantOfFinalized {
                block: signed_block,
                finalized_block: self.blocks[&self.finalized_checkpoint.root].clone(),
            },
        );

        // > Make a copy of the state to avoid mutability issues
        let mut state = pre_state.clone();
        // > Check the block is valid and compute the post-state
        process_slot::state_transition(&mut state, &signed_block, true);
        // We perform two lookups because `HashMap::entry` results in `self` being borrowed mutably.
        // See <https://doc.rust-lang.org/nomicon/lifetime-mismatch.html#limits-of-lifetimes>.
        self.block_states.insert(block_root, state);
        let state = &self.block_states[&block_root];

        // Add `block` to `self.blocks` only when it's passed all checks.
        // See <https://github.com/ethereum/eth2.0-specs/issues/1288>.
        self.blocks.insert(block_root, signed_block);

        // > Update justified checkpoint
        if self.justified_checkpoint.epoch < state.current_justified_checkpoint.epoch {
            if self.best_justified_checkpoint.epoch < state.current_justified_checkpoint.epoch {
                self.best_justified_checkpoint = state.current_justified_checkpoint;
            }
            if self.should_update_justified_checkpoint(state.current_justified_checkpoint) {
                self.justified_checkpoint = state.current_justified_checkpoint;
            }
        }

        // > Update finalized checkpoint
        if self.finalized_checkpoint.epoch < state.finalized_checkpoint.epoch {
            self.finalized_checkpoint = state.finalized_checkpoint;
            finalized_slot = Self::start_of_epoch(self.finalized_checkpoint.epoch);

            // > Update justified if new justified is later than store justified
            // > or if store justified is not in chain with finalized checkpoint
            if self.justified_checkpoint.epoch < state.current_justified_checkpoint.epoch
                || self.ancestor(self.justified_checkpoint.root, finalized_slot)
                    != self.finalized_checkpoint.root
            {
                self.justified_checkpoint = state.current_justified_checkpoint;
            }
        }

        self.retry_delayed_until_block(block_root)
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#on_attestation>
    ///
    /// All of the helpers have been inlined to avoid redundant lookups or losing ownership.
    pub fn on_attestation(&mut self, attestation: Attestation<C>) -> Result<()> {
        let target = attestation.data.target;
        let target_epoch_start = Self::start_of_epoch(target.epoch);

        // > Attestations must be from the current or previous epoch
        let current_epoch = Self::epoch_at_slot(self.slot);
        // > Use GENESIS_EPOCH for previous when genesis to avoid underflow
        let previous_epoch = current_epoch.saturating_sub(1).max(GENESIS_EPOCH);
        if target.epoch < previous_epoch {
            return Ok(());
        }
        if current_epoch < target.epoch {
            self.delay_until_slot(target_epoch_start, DelayedObject::Attestation(attestation));
            return Ok(());
        }
        ensure!(
            target.epoch == Self::epoch_at_slot(attestation.data.slot),
            Error::<C>::AttestationTargetsWrongEpoch { attestation },
        );

        // > Attestations target be for a known block.
        // > If target block is unknown, delay consideration until the block is found
        let base_state = if let Some(state) = self.block_states.get(&target.root) {
            state
        } else {
            self.delay_until_block(target.root, DelayedObject::Attestation(attestation));
            return Ok(());
        };
        // > Attestations cannot be from future epochs.
        // > If they are, delay consideration until the epoch arrives
        if self.slot < target_epoch_start {
            self.delay_until_slot(target_epoch_start, DelayedObject::Attestation(attestation));
            return Ok(());
        }

        // > Attestations must be for a known block.
        // > If block is unknown, delay consideration until the block is found
        if let Some(ghost_vote_block) = self.blocks.get(&attestation.data.beacon_block_root) {
            // > Attestations must not be for blocks in the future.
            // > If not, the attestation should not be considered
            ensure!(
                ghost_vote_block.message.slot <= attestation.data.slot,
                Error::AttestationForFutureBlock {
                    attestation,
                    block: ghost_vote_block.clone()
                },
            );
        } else {
            self.delay_until_block(
                attestation.data.beacon_block_root,
                DelayedObject::Attestation(attestation),
            );
            return Ok(());
        }

        // > Attestations can only affect the fork choice of subsequent slots.
        // > Delay consideration in the fork choice until their slot is in the past.
        if self.slot <= attestation.data.slot {
            self.delay_until_slot(
                attestation.data.slot,
                DelayedObject::Attestation(attestation),
            );
            return Ok(());
        }

        // > Store target checkpoint state if not yet seen
        // > Get state at the `target` to fully validate attestation
        let target_state = self.checkpoint_states.entry(target).or_insert_with(|| {
            let mut target_state = base_state.clone();
            process_slot::process_slots(&mut target_state, target_epoch_start);
            target_state
        });

        // > Update latest messages for attesting indices
        let new_message = LatestMessage {
            epoch: target.epoch,
            root: attestation.data.beacon_block_root,
        };

        let indexed_attestation =
            beacon_state_accessors::get_indexed_attestation(target_state, &attestation)
                .map_err(DebugAsError::new)?;

        predicates::validate_indexed_attestation(target_state, &indexed_attestation, true)
            .map_err(DebugAsError::new)?;

        for index in indexed_attestation.attesting_indices.iter().copied() {
            self.latest_messages
                .entry(index)
                .and_modify(|old_message| {
                    if old_message.epoch < new_message.epoch {
                        *old_message = new_message;
                    }
                })
                .or_insert(new_message);
        }

        Ok(())
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#compute_slots_since_epoch_start>
    fn slots_since_epoch_start(&self) -> Slot {
        self.slot - Self::start_of_epoch(Self::epoch_at_slot(self.slot))
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#get_ancestor>
    fn ancestor(&self, root: H256, slot: Slot) -> H256 {
        self.ancestor_without_lookup(root, &self.blocks[&root].message, slot)
    }

    /// The extra `block` parameter is used to avoid adding `block` to `self.blocks` before
    /// verifying it. See <https://github.com/ethereum/eth2.0-specs/issues/1288>.
    /// The parent of `block` must still be present in `self.blocks`, however.
    fn ancestor_without_lookup(&self, root: H256, block: &BeaconBlock<C>, slot: Slot) -> H256 {
        if block.slot <= slot {
            root
        } else {
            self.ancestor(block.parent_root, slot)
        }
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#get_latest_attesting_balance>
    ///
    /// The extra `block` parameter is used to avoid a redundant block lookup.
    fn latest_attesting_balance(&self, root: H256, block: &BeaconBlock<C>) -> Gwei {
        let justified_state = &self.checkpoint_states[&self.justified_checkpoint];
        let active_indices = beacon_state_accessors::get_active_validator_indices(
            justified_state,
            beacon_state_accessors::get_current_epoch(justified_state),
        );

        active_indices
            .into_iter()
            .filter_map(|index| {
                let latest_message = self.latest_messages.get(&index)?;
                if self.ancestor(latest_message.root, block.slot) == root {
                    // The `Result::expect` call would be avoidable if there were a function like
                    // `beacon_state_accessors::get_active_validator_indices` that returned
                    // references to the validators in addition to their indices.
                    let index: usize = index
                        .try_into()
                        .expect("validator index should fit in usize");
                    Some(justified_state.validators[index].effective_balance)
                } else {
                    None
                }
            })
            .sum()
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#get_filtered_block_tree>
    ///
    /// > Retrieve a filtered block tree from `store`, only returning branches
    /// > whose leaf state's justified/finalized info agrees with that in `store`.
    fn filtered_block_tree(&self) -> HashMap<H256, &SignedBeaconBlock<C>> {
        let base = self.justified_checkpoint.root;
        let mut blocks = hashmap! {};
        self.filter_block_tree(base, &mut blocks);
        blocks
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#filter_block_tree>
    fn filter_block_tree<'s>(
        &'s self,
        root: H256,
        blocks: &mut HashMap<H256, &'s SignedBeaconBlock<C>>,
    ) -> bool {
        let block = &self.blocks[&root];
        let mut children = self
            .blocks
            .iter()
            .filter_map(|(root, signed_block)| {
                if signed_block.message.parent_root == *root {
                    Some(root)
                } else {
                    None
                }
            })
            .peekable();

        // > If any children branches contain expected finalized/justified checkpoints,
        // > add to filtered block-tree and signal viability to parent.
        if children.peek().is_some() {
            if children.any(|root| self.filter_block_tree(*root, blocks)) {
                blocks.insert(root, block);
                return true;
            }
            return false;
        }

        // > If leaf block, check finalized/justified checkpoints as matching latest.
        let head_state = &self.block_states[&root];

        let correct_justified = self.justified_checkpoint.epoch == GENESIS_EPOCH
            || self.justified_checkpoint == head_state.current_justified_checkpoint;
        let correct_finalized = self.finalized_checkpoint.epoch == GENESIS_EPOCH
            || self.finalized_checkpoint == head_state.finalized_checkpoint;
        // > If expected finalized/justified,
        // > add to viable block-tree and signal viability to parent.
        if correct_justified && correct_finalized {
            blocks.insert(root, block);
            return true;
        }

        // > Otherwise, branch not viable
        false
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#get_head>
    fn head(&self) -> H256 {
        // > Get filtered block tree that only includes viable branches
        let blocks = self.filtered_block_tree();

        // > Execute the LMD-GHOST fork choice
        let mut head = self.justified_checkpoint.root;
        let justified_slot = Self::start_of_epoch(self.justified_checkpoint.epoch);

        loop {
            // > Sort by latest attesting balance with ties broken lexicographically
            let child_with_plurality = blocks
                .iter()
                .filter_map(|(root, signed_block)| {
                    let child = &signed_block.message;
                    if child.parent_root == head && justified_slot < child.slot {
                        Some((self.latest_attesting_balance(*root, child), *root))
                    } else {
                        None
                    }
                })
                .max();

            match child_with_plurality {
                Some((_, root)) => head = root,
                None => break head,
            }
        }
    }

    /// <https://github.com/ethereum/eth2.0-specs/blob/8201fb00249782528342a51434f6abcfc57b501f/specs/phase0/fork-choice.md#should_update_justified_checkpoint>
    ///
    /// > To address the bouncing attack, only update conflicting justified
    /// > checkpoints in the fork choice if in the early slots of the epoch.
    /// > Otherwise, delay incorporation of new justified checkpoint until next epoch boundary.
    /// >
    /// > See <https://ethresear.ch/t/prevention-of-bouncing-attack-on-ffg/6114> for more detailed
    /// > analysis and discussion.
    fn should_update_justified_checkpoint(&self, new_justified_checkpoint: Checkpoint) -> bool {
        if self.slots_since_epoch_start() < C::safe_slots_to_update_justified() {
            return true;
        }

        let justified_slot = Self::start_of_epoch(self.justified_checkpoint.epoch);

        self.ancestor(new_justified_checkpoint.root, justified_slot)
            == self.justified_checkpoint.root
    }

    fn start_of_epoch(epoch: Epoch) -> Slot {
        misc::compute_start_slot_at_epoch::<C>(epoch)
    }

    fn epoch_at_slot(slot: Slot) -> Epoch {
        misc::compute_epoch_at_slot::<C>(slot)
    }

    fn delay_until_block(&mut self, block_root: H256, object: DelayedObject<C>) {
        info!("object delayed until block {:?}: {:?}", block_root, object);
        self.delayed_until_block
            .entry(block_root)
            .or_default()
            .push(object)
    }

    fn delay_until_slot(&mut self, slot: Slot, object: DelayedObject<C>) {
        info!("object delayed until slot {}: {:?}", slot, object);
        self.delayed_until_slot
            .entry(slot)
            .or_default()
            .push(object)
    }

    fn retry_delayed_until_block(&mut self, block_root: H256) -> Result<()> {
        if let Some(delayed_objects) = self.delayed_until_block.remove(&block_root) {
            self.retry_delayed(delayed_objects)?;
        }
        Ok(())
    }

    fn retry_delayed_until_slot(&mut self, slot: Slot) -> Result<()> {
        let later_slots = self.delayed_until_slot.split_off(&(slot + 1));
        let fulfilled_slots = mem::replace(&mut self.delayed_until_slot, later_slots);
        for (_, objects) in fulfilled_slots {
            self.retry_delayed(objects)?;
        }
        Ok(())
    }

    // Delayed objects are retried recursively, thus a long chain of them could overflow the stack.
    // It may be that in practice only one object will be delayed for a particular reason most of
    // the time. In that case this function would effectively be tail-recursive. The same applies to
    // slots in `Store::retry_delayed_until_slot`. The `tramp` crate may be of use in that scenario.
    // Or `become`, if that ever gets implemented.
    fn retry_delayed(&mut self, objects: Vec<DelayedObject<C>>) -> Result<()> {
        for object in objects {
            info!("retrying delayed object: {:?}", object);
            match object {
                DelayedObject::Block(signed_block) => self.on_block(signed_block)?,
                DelayedObject::Attestation(attestation) => self.on_attestation(attestation)?,
            }
        }
        Ok(())
    }
}

// There used to be tests here but we were forced to omit them to save time.
