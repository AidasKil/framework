use crate::{
    crypto::{hash, hash_tree_root},
    math::{bytes_to_int, int_to_bytes},
};
use std::cmp::max;
use std::convert::TryFrom;
use std::convert::TryInto;
use tree_hash::TreeHash;
use typenum::marker_traits::Unsigned;
use types::helper_functions_types::Error;
use types::{beacon_state::BeaconState, config::Config, primitives::*, types::SigningRoot};

const MAX_RANDOM_BYTE: u64 = (1 << 8) - 1;

pub fn compute_shuffled_index<C: Config>(
    index: ValidatorIndex,
    index_count: u64,
    seed: &H256,
) -> Result<ValidatorIndex, Error> {
    if index >= index_count {
        return Err(Error::IndexOutOfRange);
    }
    let mut index = index;
    for current_round in 0..C::shuffle_round_count() {
        let pivot = bytes_to_int(hash_seed_current_round(&seed[..], current_round)) % index_count;
        let flip = (pivot + index_count - index) % index_count;
        let position = max(index, flip);
        let source = hash_seed_current_round_position(&seed[..], current_round, position);
        match usize::try_from((position % 256) / 8) {
            Ok(id) => {
                let byte = source[id];
                let bit = (byte >> (position % 8)) % 2;
                index = if bit == 0 { index } else { flip };
            }
            _ => return Err(Error::IndexOutOfRange),
        }
    }
    Ok(index)
}

fn hash_seed_current_round(seed: &[u8], current_round: u64) -> [u8; 8] {
    let mut seed = seed.to_vec();
    seed.append(&mut int_to_bytes(current_round, 1));
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&hash(&seed[..])[..8]);
    bytes
}

fn hash_seed_current_round_position(seed: &[u8], current_round: u64, position: u64) -> Vec<u8> {
    let mut seed = seed.to_vec();
    seed.append(&mut int_to_bytes(current_round, 1));
    seed.append(&mut int_to_bytes(position / 256, 4));
    hash(&seed[..])
}

pub fn compute_epoch_at_slot<C: Config>(slot: Slot) -> Epoch {
    slot / C::SlotsPerEpoch::to_u64()
}

pub fn compute_start_slot_at_epoch<C: Config>(epoch: Epoch) -> Slot {
    epoch * C::SlotsPerEpoch::to_u64()
}

pub fn compute_activation_exit_epoch<C: Config>(epoch: Epoch) -> Epoch {
    epoch + 1 + C::max_seed_lookahead()
}

pub fn compute_committee<'a, C: Config>(
    indices: &'a [ValidatorIndex],
    seed: &H256,
    index: u64,
    count: u64,
) -> Result<Vec<ValidatorIndex>, Error> {
    let start = ((indices.len() as u64) * index) / count;
    let end = ((indices.len() as u64) * (index + 1)) / count;

    let mut committee = Vec::new();
    for i in start..end {
        match compute_shuffled_index::<C>(
            i,
            usize::try_from(indices.len())
                .expect("")
                .try_into()
                .expect(""),
            seed,
        ) {
            Ok(id) => match usize::try_from(id) {
                Ok(id_usize) => committee.push(indices[id_usize]),
                Err(_) => return Err(Error::IndexOutOfRange),
            },
            Err(err) => return Err(err),
        }
    }

    Ok(committee)
}

pub fn compute_proposer_index<C: Config>(
    state: &BeaconState<C>,
    indices: &[ValidatorIndex],
    seed: &H256,
) -> Result<ValidatorIndex, Error> {
    let mut i = 0;
    loop {
        match compute_shuffled_index::<C>(i % indices.len() as u64, indices.len() as u64, seed) {
            Ok(index) => match usize::try_from(index) {
                Ok(index_usize) => {
                    let candidate_index = indices[index_usize];
                    let mut combined = seed.as_bytes().to_vec();
                    combined.append(&mut int_to_bytes(i / 32, 8));

                    let random_byte = hash(&combined)
                        [usize::try_from(i % 32).expect("Error while converting to u32")];

                    match usize::try_from(candidate_index) {
                        Ok(candidate_index_usize) => {
                            let effective_balance =
                                state.validators[candidate_index_usize].effective_balance;
                            if effective_balance * MAX_RANDOM_BYTE
                                >= C::max_effective_balance() * u64::from(random_byte)
                            {
                                break Ok(candidate_index);
                            }
                            i += 1
                        }
                        Err(_) => break Err(Error::IndexOutOfRange),
                    }
                }
                Err(_) => break Err(Error::IndexOutOfRange),
            },
            Err(err) => break Err(err),
        }
    }
}

pub fn compute_domain(domain_type: DomainType, fork_version: Option<&Version>) -> Domain {
    let version = match fork_version {
        Some(version) => version.as_array(),
        None => &[0_u8; 4],
    };

    let mut bytes = [0_u8; 8];
    (&mut bytes[0..4]).copy_from_slice(&domain_type.to_le_bytes()[0..4]);
    (&mut bytes[4..8]).copy_from_slice(version);
    bytes_to_int(bytes).into()
}

pub fn compute_signing_root<T: TreeHash>(object: &T, domain: Domain) -> H256 {
    hash_tree_root(&SigningRoot {
        object_root: hash_tree_root(object),
        domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::config::MainnetConfig;

    #[test]
    #[allow(clippy::result_unwrap_used)]
    fn test_compute_shuffled_index() {
        for i in 0..1000 {
            let shuffled_index = compute_shuffled_index::<MainnetConfig>(i, 1000, &H256::random());
            assert!(shuffled_index.is_ok());
            assert!(shuffled_index.unwrap() < 1000);
        }
    }

    #[test]
    fn test_compute_shuffled_index_index_greater_or_equal_index_count() {
        assert!(compute_shuffled_index::<MainnetConfig>(1, 1, &H256::random()).is_err());
    }

    #[test]
    fn test_epoch_of_slot() {
        let expected_epoch = 2;
        let calculated_epoch = compute_epoch_at_slot::<MainnetConfig>(65);
        assert_eq!(calculated_epoch, expected_epoch);
    }

    #[test]
    fn test_compute_start_slot_at_epoch() {
        assert_eq!(
            compute_start_slot_at_epoch::<MainnetConfig>(10_u64),
            <MainnetConfig as Config>::SlotsPerEpoch::to_u64() * 10_u64
        );
    }

    #[test]
    fn test_compute_activation_exit_epoch() {
        assert_eq!(compute_activation_exit_epoch::<MainnetConfig>(0), 5);
    }

    #[test]
    fn test_compute_domain() {
        let version = [0, 0, 0, 1].into();
        let domain_type: DomainType = 2_u32;
        let expected: u64 = 0x0100_0000_0000_0002_u64;

        assert_eq!(compute_domain(domain_type, Some(&version)), expected);
    }

    #[test]
    fn test_compute_domain_default_version() {
        let domain_type: DomainType = 2_u32;
        let expected: u64 = 0x0000_0000_0000_0002_u64;

        assert_eq!(compute_domain(domain_type, None), expected);
    }
}
