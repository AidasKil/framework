use helper_functions;
use types::consts::*;
use types::{
    beacon_state::*,
    config::{Config, MainnetConfig},
};
// use types::types::*;
use crate::attestations::attestations::AttestableBlock;
use helper_functions::beacon_state_accessors::*;
use helper_functions::beacon_state_mutators::*;
use helper_functions::math::*;
use helper_functions::predicates::*;
use types::primitives::*;

pub trait StakeholderBlock<T>
where
    T: Config,
{
    fn get_base_reward(&self, index: ValidatorIndex) -> Gwei;
    fn get_attestation_deltas(&self) -> (Vec<Gwei>, Vec<Gwei>);
    fn process_rewards_and_penalties(&mut self);
}

impl<T> StakeholderBlock<T> for BeaconState<T>
where
    T: Config,
{
    fn get_base_reward(&self, index: ValidatorIndex) -> Gwei {
        let total_balance = get_total_active_balance(&self).unwrap();
        let effective_balance = self.validators[index as usize].effective_balance;
        return (effective_balance * T::base_reward_factor()
            / integer_squareroot(total_balance)
            / BASE_REWARDS_PER_EPOCH) as Gwei;
    }

    fn get_attestation_deltas(&self) -> (Vec<Gwei>, Vec<Gwei>) {
        let previous_epoch = get_previous_epoch(self);
        let total_balance = get_total_active_balance(self).unwrap();
        let mut rewards = Vec::new();
        let mut penalties = Vec::new();
        for _i in 0..(self.validators.len()) {
            rewards.push(0 as Gwei);
            penalties.push(0 as Gwei);
        }
        let mut eligible_validator_indices: Vec<ValidatorIndex> = Vec::new();

        for (index, v) in self.validators.iter().enumerate() {
            if is_active_validator(v, previous_epoch)
                || (v.slashed && previous_epoch + 1 < v.withdrawable_epoch)
            {
                eligible_validator_indices.push(index as ValidatorIndex);
            }
        }

        //# Micro-incentives for matching FFG source, FFG target, and head
        let matching_source_attestations = self.get_matching_source_attestations(previous_epoch);
        let matching_target_attestations = self.get_matching_target_attestations(previous_epoch);
        let matching_head_attestations = self.get_matching_head_attestations(previous_epoch);
        let vec = vec![
            matching_source_attestations.clone(),
            matching_target_attestations.clone(),
            matching_head_attestations.clone(),
        ];

        for attestations in vec.into_iter() {
            let unslashed_attesting_indices = self.get_unslashed_attesting_indices(attestations);
            let attesting_balance = get_total_balance(self, &unslashed_attesting_indices).unwrap();

            for index in eligible_validator_indices.iter() {
                if unslashed_attesting_indices.contains(&index) {
                    rewards[*index as usize] += ((self.get_base_reward(*index) * attesting_balance)
                        / total_balance)
                        as ValidatorIndex;
                } else {
                    penalties[*index as usize] += self.get_base_reward(*index);
                }
            }
        }

        //# Proposer and inclusion delay micro-rewards
        for index in self
            .get_unslashed_attesting_indices(matching_source_attestations.clone())
            .iter()
        {
            let attestation = matching_source_attestations
                .into_iter()
                .filter(|attestation| {
                    get_attesting_indices(self, &attestation.data, &attestation.aggregation_bits)
                        .expect("get_attesting_indices should succeed")
                        .contains(index)
                })
                .min_by_key(|attestation| attestation.inclusion_delay)
                .expect("at least one matching attestation should exist");

            let proposer_reward =
                (self.get_base_reward(*index) / T::proposer_reward_quotient()) as Gwei;
            rewards[attestation.proposer_index as usize] += proposer_reward;
            let max_attester_reward = self.get_base_reward(*index) - proposer_reward;
            rewards[*index as usize] += (max_attester_reward / attestation.inclusion_delay) as Gwei;
        }
        //# Inactivity penalty
        let finality_delay = previous_epoch - self.finalized_checkpoint.epoch;
        if finality_delay > T::min_epochs_to_inactivity_penalty() {
            let matching_target_attesting_indices =
                self.get_unslashed_attesting_indices(matching_target_attestations);
            for index in eligible_validator_indices {
                penalties[index as usize] +=
                    (BASE_REWARDS_PER_EPOCH * self.get_base_reward(index)) as Gwei;
                if !(matching_target_attesting_indices.contains(&index)) {
                    penalties[index as usize] +=
                        ((self.validators[index as usize].effective_balance * finality_delay)
                            / T::inactivity_penalty_quotient()) as Gwei;
                }
            }
        }
        return (rewards, penalties);
    }

    fn process_rewards_and_penalties(&mut self) {
        if get_current_epoch(&self) == GENESIS_EPOCH {
            return;
        }
        let (rewards, penalties) = self.get_attestation_deltas();
        for index in 0..self.validators.len() {
            increase_balance(self, index as u64, rewards[index]).unwrap();
            decrease_balance(self, index as u64, penalties[index]).unwrap();
        }
    }
}

#[test]
fn test_base_reward() {
    use types::types::Validator;
    assert_eq!(1, 1);
    let mut bs: BeaconState<MainnetConfig> = BeaconState {
        ..BeaconState::default()
    };
    let mut val: Validator = Validator {
        ..Validator::default()
    };
    val.effective_balance = 5;
    val.slashed = false;
    bs.validators.push(val).unwrap();
    let mut index = 0;
    assert_eq!(5 * 64 / 4, bs.get_base_reward(index));
}
