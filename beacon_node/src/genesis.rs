use core::convert::TryInto as _;

use anyhow::{ensure, Result};
use helper_functions::{beacon_state_accessors, crypto};
use ssz_types::FixedVector;
use thiserror::Error;
use transition_functions::blocks::block_processing;
use types::{
    beacon_state::BeaconState,
    config::Config,
    consts::{GENESIS_EPOCH, GENESIS_SLOT},
    primitives::{UnixSeconds, ValidatorIndex, H256},
    types::{
        BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Deposit, Eth1Data, Fork, SignedBeaconBlock,
    },
};

use crate::deposit_tree::DepositTree;

#[derive(Debug, Error)]
enum Error {
    #[error("genesis is too early ({genesis_time} < {minimum_genesis_time})")]
    GenesisTooEarly {
        genesis_time: UnixSeconds,
        minimum_genesis_time: UnixSeconds,
    },
    #[error("not enough active validators ({validator_count} < {minimum_validator_count})")]
    NotEnoughActiveValidators {
        validator_count: ValidatorIndex,
        minimum_validator_count: ValidatorIndex,
    },
}

/// <https://github.com/ethereum/eth2.0-specs/blob/5e1fb79a8e312ac03992b834f48c88edab240eb6/specs/phase0/beacon-chain.md#genesis>
pub fn state<C: Config>(
    eth1_block_hash: H256,
    eth1_block_timestamp: UnixSeconds,
    deposits: &[Deposit],
) -> Result<BeaconState<C>> {
    let slot = GENESIS_SLOT;
    let version = C::genesis_fork_version();

    let mut genesis_state = BeaconState {
        genesis_time: floor_to_multiple(eth1_block_timestamp, C::min_genesis_delay())
            + 2 * C::min_genesis_delay(),
        slot,
        fork: Fork {
            previous_version: version,
            current_version: version,
            epoch: GENESIS_EPOCH,
        },
        latest_block_header: BeaconBlockHeader {
            slot,
            body_root: crypto::hash_tree_root(&BeaconBlockBody::<C>::default()),
            ..BeaconBlockHeader::default()
        },
        eth1_data: Eth1Data {
            deposit_count: deposits.len().try_into()?,
            block_hash: eth1_block_hash,
            ..Eth1Data::default()
        },
        randao_mixes: FixedVector::from_elem(eth1_block_hash),
        ..BeaconState::default()
    };

    // > Process deposits
    let mut deposit_tree = DepositTree::default();
    for deposit in deposits {
        let (_, root) = deposit_tree.add_deposit(&deposit.data)?;
        genesis_state.eth1_data.deposit_root = root;
        block_processing::process_deposit(&mut genesis_state, deposit);
    }

    // > Process activations
    for (balance, validator) in genesis_state
        .balances
        .iter()
        .zip(genesis_state.validators.iter_mut())
    {
        validator.effective_balance = floor_to_multiple(*balance, C::effective_balance_increment())
            .min(C::max_effective_balance());
        if validator.effective_balance == C::max_effective_balance() {
            validator.activation_eligibility_epoch = GENESIS_EPOCH;
            validator.activation_epoch = GENESIS_EPOCH;
        }
    }

    Ok(genesis_state)
}

/// <https://github.com/ethereum/eth2.0-specs/blob/5e1fb79a8e312ac03992b834f48c88edab240eb6/specs/phase0/beacon-chain.md#genesis-state>
pub fn validate_state<C: Config>(state: &BeaconState<C>) -> Result<()> {
    let genesis_time = state.genesis_time;
    let minimum_genesis_time = C::min_genesis_time();
    ensure!(
        minimum_genesis_time <= genesis_time,
        Error::GenesisTooEarly {
            genesis_time,
            minimum_genesis_time
        },
    );

    let validator_count =
        beacon_state_accessors::get_active_validator_indices(state, GENESIS_EPOCH)
            .len()
            .try_into()?;
    let minimum_validator_count = C::min_genesis_active_validator_count();
    ensure!(
        minimum_validator_count <= validator_count,
        Error::NotEnoughActiveValidators {
            validator_count,
            minimum_validator_count,
        },
    );

    Ok(())
}

/// <https://github.com/ethereum/eth2.0-specs/blob/5e1fb79a8e312ac03992b834f48c88edab240eb6/specs/phase0/beacon-chain.md#genesis-block>
pub fn block<C: Config>(genesis_state: &BeaconState<C>) -> SignedBeaconBlock<C> {
    // The way the genesis block is constructed makes it possible for many parties to independently
    // produce the same block. But why does the genesis block have to exist at all? Perhaps the
    // first block could be proposed by a validator as well (and not necessarily in slot 0)?
    SignedBeaconBlock {
        message: BeaconBlock {
            // Note that `body.eth1_data` is not set to `genesis_state.latest_eth1_data`.
            state_root: crypto::hash_tree_root(genesis_state),
            ..BeaconBlock::default()
        },
        ..SignedBeaconBlock::default()
    }
}

const fn floor_to_multiple(number: u64, factor: u64) -> u64 {
    // This could also be written as `number / factor * factor`.
    number - number % factor
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::config::MinimalConfig;

    use super::*;

    // We do not honor `bls_setting` in genesis tests because none of them customize it.
    //
    // The globs passed to `test_resources` match all configuration presets but we run the test
    // cases with `MinimalConfig` because genesis tests are only provided for the minimal preset.

    #[test_resources("eth2.0-spec-tests/tests/*/phase0/genesis/initialization/*/*")]
    fn initialization(case: Case) {
        let eth1_block_hash = case.yaml("eth1_block_hash");
        let eth1_block_timestamp = case.yaml("eth1_timestamp");
        let deposits = case
            .iterator("deposits", case.meta().deposits_count)
            .collect::<Vec<_>>();
        let expected_genesis_state = case.ssz("state");

        let actual_genesis_state =
            state::<MinimalConfig>(eth1_block_hash, eth1_block_timestamp, deposits.as_slice())
                .expect("every genesis initialization test should result in a valid state");

        assert_eq!(actual_genesis_state, expected_genesis_state);
    }

    #[test_resources("eth2.0-spec-tests/tests/*/phase0/genesis/validity/*/*")]
    fn validity(case: Case) {
        let genesis_state = case.ssz("genesis");
        let is_valid = case.yaml("is_valid");

        assert_eq!(
            validate_state::<MinimalConfig>(&genesis_state).is_ok(),
            is_valid,
        );
    }
}
