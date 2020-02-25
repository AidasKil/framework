use core::convert::TryInto as _;

use crate::*;
use blocks::block_processing::*;
use epochs::process_epoch::process_epoch;
use ethereum_types::H256 as Hash256;
use helper_functions::{beacon_state_accessors::*, crypto::*, misc::*};
use typenum::Unsigned as _;
use types::primitives::*;
use types::types::*;
use types::{
    beacon_state::*,
    config::{Config, MainnetConfig},
    types::BeaconBlockHeader,
};
#[derive(Debug, PartialEq)]
pub enum Error {}

pub fn state_transition<T: Config>(
    state: &mut BeaconState<T>,
    signed_block: &SignedBeaconBlock<T>,
    validate_result: bool,
) -> BeaconState<T> {
    let block = &signed_block.message;
    //# Process slots (including those with no blocks) since block
    process_slots(state, block.slot);
    //# Verify signature
    if validate_result {
        assert!(verify_block_signature(state, signed_block));
    }
    //# Process block
    blocks::block_processing::process_block(state, &signed_block.message);
    //# Verify state root
    if validate_result {
        assert!(block.state_root == hash_tree_root(state));
    }
    //# Return post-state
    return state.clone();
}

pub fn process_slots<T: Config>(state: &mut BeaconState<T>, slot: Slot) {
    assert!(state.slot <= slot);
    while state.slot < slot {
        process_slot(state);
        //# Process epoch on the start slot of the next epoch
        if (state.slot + 1) % T::SlotsPerEpoch::U64 == 0 {
            process_epoch(state);
        }
        state.slot += 1;
    }
}

fn process_slot<T: Config>(state: &mut BeaconState<T>) {
    // Cache state root
    let previous_state_root = hash_tree_root(state);

    state.state_roots[(state.slot as usize) % T::SlotsPerHistoricalRoot::USIZE] =
        previous_state_root;
    // Cache latest block header state root
    if state.latest_block_header.state_root == H256::from([0 as u8; 32]) {
        state.latest_block_header.state_root = previous_state_root;
    }
    // Cache block root
    let previous_block_root = hash_tree_root(&state.latest_block_header);
    state.block_roots[(state.slot as usize) % T::SlotsPerHistoricalRoot::USIZE] =
        previous_block_root;
}

fn verify_block_signature<C: Config>(
    state: &BeaconState<C>,
    signed_block: &SignedBeaconBlock<C>,
) -> bool {
    let proposer = &state.validators[get_beacon_proposer_index(&state).unwrap() as usize];
    let domain = get_domain(state, C::domain_beacon_proposer(), None);
    let signing_root = compute_signing_root(&signed_block.message, domain);
    bls_verify(
        &proposer.pubkey,
        signing_root.as_bytes(),
        &signed_block.signature,
    )
    .unwrap()
}

/*
pub fn process_slot<T: Config>(state: &mut BeaconState<T>, genesis_slot: u64) -> Result<(), Error> {
    cache_state(state)?;

    if state.slot > genesis_slot
    && (state.slot + 1) % T::slots_per_epoch() == 0
    {
        process_epoch(state);
    }

    state.slot += 1;

    Ok(())
}

fn cache_state<T: Config>(state: &mut BeaconState<T>) -> Result<(), Error> {
    let previous_state_root = state.update_tree_hash_cache().unwrap(); //?;
    let previous_slot = state.slot;

    // ! FIX THIS :( @pikaciu22x
    state.slot += 1;

    state.set_state_root(previous_slot, previous_state_root); //?;

    if state.latest_block_header.state_root == Hash256::zero() {
        state.latest_block_header.state_root = previous_state_root;
    }

    let latest_block_root = state.latest_block_header.canonical_root();
    state.set_block_root(previous_slot, latest_block_root); //?;

    state.slot -= 1;

    Ok(())
}
*/
#[cfg(test)]
mod process_slot_tests {
    use types::{beacon_state::*, config::MainnetConfig};
    // use crate::{config::*};
    use super::*;

    #[test]
    fn process_good_slot() {
        let mut bs: BeaconState<MainnetConfig> = BeaconState {
            ..BeaconState::default()
        };

        process_slots(&mut bs, 1);

        assert_eq!(bs.slot, 1);
    }
    #[test]
    fn process_good_slot_2() {
        let mut bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 3,
            ..BeaconState::default()
        };

        process_slots(&mut bs, 4);
        //assert_eq!(bs.slot, 6);
    }
}

#[cfg(test)]
mod spec_tests {
    use test_generator::test_resources;
    use types::config::MinimalConfig;

    use super::*;

    // We do not honor `bls_setting` in sanity tests because none of them customize it.

    #[test_resources("eth2.0-spec-tests/tests/mainnet/phase0/sanity/slots/*/*")]
    fn mainnet_slots(case_directory: &str) {
        run_slots_case::<MainnetConfig>(case_directory);
    }

    #[test_resources("eth2.0-spec-tests/tests/minimal/phase0/sanity/slots/*/*")]
    fn minimal_slots(case_directory: &str) {
        run_slots_case::<MinimalConfig>(case_directory);
    }

    #[test_resources("eth2.0-spec-tests/tests/mainnet/phase0/sanity/blocks/*/*")]
    fn mainnet_blocks(case_directory: &str) {
        run_blocks_case::<MainnetConfig>(case_directory);
    }

    #[test_resources("eth2.0-spec-tests/tests/minimal/phase0/sanity/blocks/*/*")]
    fn minimal_blocks(case_directory: &str) {
        run_blocks_case::<MinimalConfig>(case_directory);
    }

    fn run_slots_case<C: Config>(case_directory: &str) {
        let mut state: BeaconState<C> = spec_test_utils::pre(case_directory);
        let last_slot = state.slot + spec_test_utils::slots(case_directory);
        let expected_post = spec_test_utils::post(case_directory)
            .expect("every slot sanity test should have a post-state");

        process_slots(&mut state, last_slot);

        assert_eq!(state, expected_post);
    }

    fn run_blocks_case<C: Config>(case_directory: &str) {
        let process_blocks = || {
            let mut state = spec_test_utils::pre(case_directory);
            for block in spec_test_utils::blocks(case_directory) {
                state_transition::<C>(&mut state, &block, true);
            }
            state
        };
        match spec_test_utils::post(case_directory) {
            Some(expected_post) => assert_eq!(process_blocks(), expected_post),
            // The state transition code as it is now panics on error instead of returning `Result`.
            // We have to use `std::panic::catch_unwind` to verify that state transitions fail.
            // This may result in tests falsely succeeding.
            None => assert!(std::panic::catch_unwind(process_blocks).is_err()),
        }
    }
}
