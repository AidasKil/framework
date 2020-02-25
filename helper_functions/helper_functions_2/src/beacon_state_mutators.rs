use super::beacon_state_accessors as accessors;
use crate::beacon_state_accessors::get_current_epoch;
use crate::beacon_state_accessors::get_validator_churn_limit;
use crate::misc::compute_activation_exit_epoch;
use std::cmp;
use std::convert::TryFrom;
use typenum::Unsigned;
use types::beacon_state::BeaconState;
use types::config::Config;
use types::consts::FAR_FUTURE_EPOCH;
use types::helper_functions_types::Error;
use types::primitives::{Epoch, Gwei, ValidatorIndex};

pub fn increase_balance<C: Config>(
    state: &mut BeaconState<C>,
    index: ValidatorIndex,
    delta: Gwei,
) -> Result<(), Error> {
    let balances_size = state.balances.len();
    if usize::try_from(index).expect("") >= balances_size {
        return Err(Error::IndexOutOfRange);
    }
    state.balances[usize::try_from(index).expect("")] += delta;
    Ok(())
}

pub fn decrease_balance<C: Config>(
    state: &mut BeaconState<C>,
    index: ValidatorIndex,
    delta: Gwei,
) -> Result<(), Error> {
    let balances_size = state.balances.len();
    if usize::try_from(index).expect("") >= balances_size {
        return Err(Error::IndexOutOfRange);
    }
    if delta > state.balances[usize::try_from(index).expect("")] {
        state.balances[usize::try_from(index).expect("")] = 0;
    } else {
        state.balances[usize::try_from(index).expect("")] -= delta;
    }
    Ok(())
}

pub fn slash_validator<C: Config>(
    state: &mut BeaconState<C>,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
) -> Result<(), Error> {
    let epoch: Epoch = get_current_epoch(state);
    initiate_validator_exit(state, slashed_index)?;
    let sl_index = usize::try_from(slashed_index)
        .expect("Conversion to usize for indexing would truncate the value of ValidatorIndex");
    let validator = &mut state.validators[sl_index];
    validator.slashed = true;
    let epochs_per_slashings = C::EpochsPerSlashingsVector::to_u64();
    validator.withdrawable_epoch =
        cmp::max(validator.withdrawable_epoch, epoch + epochs_per_slashings);
    let effective_balance = validator.effective_balance;
    let slashings_index = usize::try_from(epoch % epochs_per_slashings)
        .expect("Conversion to usize for indexing would truncate the value of ValidatorIndex");
    state.slashings[slashings_index] += effective_balance;
    let decr = validator.effective_balance / C::min_slashing_penalty_quotient();
    decrease_balance(state, slashed_index, decr)?;

    // Apply proposer and whistleblower rewards
    let proposer_index = accessors::get_beacon_proposer_index(state)?;
    let whistleblower_ind_val = match whistleblower_index {
        None => proposer_index,
        Some(i) => i,
    };
    let whistleblower_reward = effective_balance / C::whistleblower_reward_quotient();
    let proposer_reward = whistleblower_reward / C::proposer_reward_quotient();
    increase_balance(state, proposer_index, proposer_reward)?;
    increase_balance(
        state,
        whistleblower_ind_val,
        whistleblower_reward - proposer_reward,
    )?;
    Ok(())
}

pub fn initiate_validator_exit<C: Config>(
    state: &mut BeaconState<C>,
    index: ValidatorIndex,
) -> Result<(), Error> {
    let mut validator = state.validators[usize::try_from(index).expect("")].clone();
    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }
    let validators_number = state.validators.len();

    // get exit epochs of all validators
    let mut exit_epochs: Vec<Epoch> = Vec::with_capacity(validators_number);
    for i in 0..validators_number {
        if state.validators[i].exit_epoch != FAR_FUTURE_EPOCH {
            exit_epochs.push(state.validators[i].exit_epoch);
        }
    }

    // get the possible exit epoch - by MIN_SEED_LOOK_AHEAD or the last validator in queue:
    let current_epoch: Epoch = get_current_epoch(state);
    let mut exit_queue_epoch: Epoch = compute_activation_exit_epoch::<C>(current_epoch);
    let iter = exit_epochs.iter();
    for i in iter {
        if *i > exit_queue_epoch {
            exit_queue_epoch = *i;
        }
    }

    // check if number of exiting validators does not exceed churn limit
    let mut exit_queue_churn = 0;
    let iter = exit_epochs.iter();
    for i in iter {
        if *i == exit_queue_epoch {
            exit_queue_churn += 1;
        }
    }
    if exit_queue_churn >= get_validator_churn_limit(state).expect("Expected success") {
        exit_queue_epoch += 1;
    }

    // change validator's exit epoch in the beacon chain
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch = validator.exit_epoch + C::min_validator_withdrawability_delay();
    state.validators[usize::try_from(index).expect("")] = validator;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::{PublicKey, SecretKey};
    use types::config::{MainnetConfig, MinimalConfig};
    use types::primitives::H256;
    use types::types::Validator;

    const EPOCH_MAX: u64 = u64::max_value();

    fn default_validator() -> Validator {
        Validator {
            effective_balance: 0,
            slashed: false,
            activation_eligibility_epoch: EPOCH_MAX,
            activation_epoch: 0,
            exit_epoch: EPOCH_MAX,
            withdrawable_epoch: EPOCH_MAX,
            withdrawal_credentials: H256([0; 32]),
            pubkey: PublicKey::from_secret_key(&SecretKey::random()).into(),
        }
    }

    mod slash_validator_tests {
        use super::*;

        #[test]
        fn test_exit_epoch() {
            let mut state: BeaconState<MainnetConfig> = BeaconState::default();
            state.slot = <MainnetConfig as Config>::SlotsPerEpoch::to_u64() * 3;
            // Add validator and it's balance
            state
                .validators
                .push(default_validator())
                .expect("Expected successess");
            state.balances.push(100).expect("Expected success");

            let mut state_copy = state.clone();
            initiate_validator_exit(&mut state_copy, 0)
                .expect("Expected successful initiate_validator_exit");

            slash_validator(&mut state, 0, None).expect("slash_validator should succeed");

            assert_eq!(
                state_copy.validators[0].exit_epoch,
                state.validators[0].exit_epoch
            );
        }
    }

    #[test]
    fn test_validator_exit_init() {
        let mut state = BeaconState::<MinimalConfig>::default();

        let val1: Validator = Validator {
            activation_eligibility_epoch: 2,
            activation_epoch: 3,
            effective_balance: 24,
            exit_epoch: 4,
            pubkey: PublicKey::from_secret_key(&SecretKey::random()).into(),
            slashed: false,
            withdrawable_epoch: 9999,
            withdrawal_credentials: H256([0; 32]),
        };

        let val2: Validator = Validator {
            activation_eligibility_epoch: 2,
            activation_epoch: 3,
            effective_balance: 24,
            exit_epoch: FAR_FUTURE_EPOCH,
            pubkey: PublicKey::from_secret_key(&SecretKey::random()).into(),
            slashed: false,
            withdrawable_epoch: 9999,
            withdrawal_credentials: H256([0; 32]),
        };

        state.validators.push(val1).expect("");
        state.validators.push(val2).expect("");
        // 1 - exit epoch is already set and should remain the same
        let expected_exit_epoch: Epoch = 4;
        initiate_validator_exit(&mut state, 0).expect("");
        assert_eq!(expected_exit_epoch, state.validators[0].exit_epoch);
        assert_ne!(5, state.validators[0].exit_epoch);
        // 2 - exit epoch is FAR_FUTURE epoch and should be set to the lowest possible value
        initiate_validator_exit(&mut state, 1).expect("");
        assert_ne!(FAR_FUTURE_EPOCH, state.validators[1].exit_epoch);
        assert_eq!(4, state.validators[1].exit_epoch);
        // same exit epoch as val1, because churn is not exceeded
    }

    #[test]
    fn test_increase_balance() {
        let mut state = BeaconState::<MinimalConfig>::default();
        state.balances.push(5).expect("");
        increase_balance(&mut state, 0, 10).expect("");
        assert_eq!(state.balances[0], 15);
    }

    #[test]
    fn test_decrease_balance() {
        let mut state = BeaconState::<MinimalConfig>::default();
        state.balances.push(5).expect("");
        decrease_balance(&mut state, 0, 10).expect("");
        assert_eq!(state.balances[0], 0);
        state.balances.push(10).expect("");
        decrease_balance(&mut state, 1, 5).expect("");
        assert_eq!(state.balances[1], 5);
    }
}
