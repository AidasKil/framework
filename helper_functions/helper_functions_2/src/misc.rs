use crate::crypto::{hash, hash_tree_root};
use crate::math::bytes_to_int;
use crate::math::int_to_bytes;

use std::convert::TryFrom;
use std::convert::TryInto;
use tree_hash::TreeHash;
use typenum::marker_traits::Unsigned;
use types::beacon_state::BeaconState;
use types::config::Config;
use types::helper_functions_types::Error;
use types::primitives::{Domain, DomainType, Epoch, Slot, ValidatorIndex, Version, H256};
use types::types::SigningRoot;

pub fn compute_epoch_at_slot<C: Config>(slot: Slot) -> Epoch {
    slot / C::SlotsPerEpoch::to_u64()
}

pub fn compute_start_slot_at_epoch<C: Config>(epoch: Epoch) -> Slot {
    epoch * C::SlotsPerEpoch::to_u64()
}

pub fn compute_activation_exit_epoch<C: Config>(epoch: Epoch) -> Epoch {
    epoch + 1 + C::max_seed_lookahead()
}

pub fn compute_domain(domain_type: DomainType, fork_version: Option<&Version>) -> Domain {
    let domain_type_bytes = int_to_bytes(u64::try_from(domain_type).expect(""), 4).expect("");
    let mut domain_bytes = [0, 0, 0, 0, 0, 0, 0, 0];
    for i in 0..4 {
        domain_bytes[i] = domain_type_bytes[i];
        if let Some(f) = fork_version {
            domain_bytes[i + 4] = f[i];
        }
    }
    bytes_to_int(&domain_bytes).expect("").into()
}

pub fn compute_signing_root<T: TreeHash>(object: &T, domain: Domain) -> H256 {
    hash_tree_root(&SigningRoot {
        object_root: hash_tree_root(object),
        domain,
    })
}

pub fn compute_shuffled_index<C: Config>(
    index: ValidatorIndex,
    index_count: u64,
    seed: &H256,
) -> Result<ValidatorIndex, Error> {
    if index > index_count {
        return Err(Error::IndexOutOfRange);
    }

    let mut ind = index;
    for current_round in 0..C::shuffle_round_count() {
        // compute pivot
        let seed_bytes = seed.as_bytes();
        let round_bytes: Vec<u8> = int_to_bytes(current_round, 1).expect("");
        let mut sum_vec: Vec<u8> = Vec::new();
        let iter = seed_bytes.iter();
        for i in iter {
            sum_vec.push(*i);
        }
        sum_vec.push(round_bytes[0]);
        let hashed_value = hash(sum_vec.as_mut_slice());
        let mut hash_8_bytes: Vec<u8> = Vec::new();
        let iter = hashed_value.iter().take(8);
        for i in iter {
            hash_8_bytes.push(*i);
        }
        let pivot = bytes_to_int(hash_8_bytes.as_mut_slice()).expect("") % index_count;
        // compute flip
        let flip = (pivot + index_count - ind) % index_count;
        // compute position
        let position = if ind > flip { ind } else { flip };
        // compute source
        let addition_to_sum: Vec<u8> = int_to_bytes(position / 256, 4).expect("");
        let iter = addition_to_sum.iter();
        for i in iter {
            sum_vec.push(*i);
        }
        let source = hash(sum_vec.as_mut_slice());
        // compute byte
        let byte = source[usize::try_from((position % 256) / 8).expect("")];
        // compute bit
        let bit: u8 = (byte >> (position % 8)) % 2;
        // flip or not?
        if bit == 1 {
            ind = flip;
        }
    }
    Ok(ind)
}

pub fn compute_proposer_index<C: Config>(
    state: &BeaconState<C>,
    indices: &[ValidatorIndex],
    seed: &H256,
) -> Result<ValidatorIndex, Error> {
    if indices.is_empty() {
        return Err(Error::ArrayIsEmpty);
    }
    let max_random_byte = 255;
    let mut i = 0;
    loop {
        let candidate_index = indices[usize::try_from(
            compute_shuffled_index::<C>(i % indices.len() as u64, indices.len() as u64, seed)
                .expect(""),
        )
        .expect("")];
        let rand_bytes = int_to_bytes(i / 32, 8).expect("");
        let mut seed_and_bytes: Vec<u8> = Vec::new();
        for i in 0..32 {
            seed_and_bytes.push(seed[i]);
        }
        let iter = rand_bytes.iter().take(8);
        for i in iter {
            seed_and_bytes.push(*i);
        }
        let hashed_seed_and_bytes = hash(seed_and_bytes.as_mut_slice());
        let random_byte = hashed_seed_and_bytes[usize::try_from(i % 32).expect("")];
        let effective_balance =
            state.validators[usize::try_from(candidate_index).expect("")].effective_balance;
        if effective_balance * max_random_byte
            >= C::max_effective_balance() * u64::from(random_byte)
        {
            return Ok(candidate_index);
        }
        i += 1;
    }
}

pub fn compute_committee<'a, C: Config>(
    indices: &'a [ValidatorIndex],
    seed: &H256,
    index: u64,
    count: u64,
) -> Result<Vec<ValidatorIndex>, Error> {
    let start = ((indices.len() as u64) * index) / count;
    let end = ((indices.len() as u64) * (index + 1)) / count;
    let mut committee_vec: Vec<ValidatorIndex> = Vec::new();
    for i in start..end {
        committee_vec.push(
            indices[usize::try_from(
                compute_shuffled_index::<C>(
                    i,
                    usize::try_from(indices.len())
                        .expect("")
                        .try_into()
                        .expect(""),
                    seed,
                )
                .expect(""),
            )
            .expect("")],
        );
    }
    Ok(committee_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::{PublicKey, SecretKey};
    use types::config::MinimalConfig;
    use types::consts::FAR_FUTURE_EPOCH;
    use types::types::Validator;

    #[test]
    fn test_epoch_at_slot() {
        // Minimalconfig: SlotsPerEpoch = 32; epochs indexed from 0
        assert_eq!(compute_epoch_at_slot::<MinimalConfig>(33), 1);
        assert_eq!(compute_epoch_at_slot::<MinimalConfig>(32), 1);
        assert_eq!(compute_epoch_at_slot::<MinimalConfig>(31), 0);
    }

    #[test]
    fn test_start_slot_at_epoch() {
        assert_eq!(compute_start_slot_at_epoch::<MinimalConfig>(1), 8);
        assert_ne!(compute_start_slot_at_epoch::<MinimalConfig>(1), 7);
        assert_ne!(compute_start_slot_at_epoch::<MinimalConfig>(1), 9);
    }

    #[test]
    fn test_activation_exit_epoch() {
        assert_eq!(compute_activation_exit_epoch::<MinimalConfig>(1), 3);
    }

    #[test]
    fn test_compute_domain() {
        let domain: Domain = compute_domain(1, Some(&[0, 0, 0, 1].into()));
        assert_eq!(domain, 0x0001_0000_0001);
        // 1 * 256 ^ 4 + 1 = 4294967297 = 0x0001_0000_0001
    }
    #[test]
    fn test_compute_shuffled_index() {
        let test_indices_length = 25;
        for _i in 0..20 {
            let shuffled_index: ValidatorIndex =
                compute_shuffled_index::<MinimalConfig>(2, test_indices_length, &H256::random())
                    .expect("");
            let in_range = if shuffled_index >= test_indices_length {
                0
            } else {
                1
            };
            // if shuffled index is not one of the validators indices (0, ..., test_indices_length - 1), panic.
            assert_eq!(1, in_range);
        }
    }

    #[test]
    fn test_compute_proposer_index() {
        let mut state = BeaconState::<MinimalConfig>::default();

        let val1: Validator = Validator {
            activation_eligibility_epoch: 2,
            activation_epoch: 3,
            effective_balance: 0,
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
        let index: ValidatorIndex =
            compute_proposer_index(&state, &[0, 1], &H256::random()).expect("");
        let in_range = if index >= 2 { 0 } else { 1 };
        assert_eq!(1, in_range);
    }

    #[test]
    fn test_compute_committee() {
        let mut test_vec: Vec<ValidatorIndex> = Vec::new();
        for i in 0..100 {
            test_vec.push(i);
        }
        let committee: Vec<ValidatorIndex> =
            compute_committee::<MinimalConfig>(&test_vec, &H256::random(), 2, 20).expect("");
        assert_eq!(5, committee.len());
    }
}
