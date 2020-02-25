use crate::{
    beacon_state_accessors,
    crypto::{bls_verify, hash},
    misc,
};
use std::convert::{TryFrom, TryInto as _};
use typenum::marker_traits::Unsigned;
use types::helper_functions_types::Error;
use types::{
    beacon_state::BeaconState,
    config::Config,
    primitives::*,
    types::{AttestationData, IndexedAttestation, Validator},
};

pub fn is_slashable_validator(validator: &Validator, epoch: Epoch) -> bool {
    !validator.slashed
        && validator.activation_epoch <= epoch
        && epoch < validator.withdrawable_epoch
}

pub fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}

pub fn is_slashable_attestation_data(data_1: &AttestationData, data_2: &AttestationData) -> bool {
    // Double vote
    (data_1 != data_2 && data_1.target.epoch == data_2.target.epoch) ||
    // Surround vote
    (data_1.source.epoch < data_2.source.epoch && data_2.target.epoch < data_1.target.epoch)
}

pub fn validate_indexed_attestation<C: Config>(
    state: &BeaconState<C>,
    indexed_attestation: &IndexedAttestation<C>,
    verify_signature: bool,
) -> Result<(), Error> {
    let indices = &indexed_attestation.attesting_indices;

    // Verify max number of indices
    if indices.len() >= C::MaxValidatorsPerCommittee::to_usize() {
        return Err(Error::IndicesExceedMaxValidators);
    }

    // Verify indices are sorted
    let is_sorted = indices.windows(2).all(|w| w[0] <= w[1]);
    if !is_sorted {
        return Err(Error::IndicesNotSorted);
    }

    let mut pubkeys = AggregatePublicKey::new();

    for i in indices.iter() {
        match usize::try_from(*i) {
            Err(_) => return Err(Error::IndexOutOfRange),
            Ok(id) => match state.validators.get(id) {
                None => return Err(Error::IndexOutOfRange),
                Some(validator) => pubkeys.add(&(&validator.pubkey).try_into()?),
            },
        }
    }

    let pubkeys_bytes = match PublicKeyBytes::from_bytes(pubkeys.as_raw().as_bytes().as_slice()) {
        Ok(value) => value,
        Err(_) => return Err(Error::PubKeyConversionError),
    };

    let domain = beacon_state_accessors::get_domain(
        state,
        C::domain_beacon_attester(),
        Some(indexed_attestation.data.target.epoch),
    );

    let signing_root = misc::compute_signing_root(&indexed_attestation.data, domain);

    let signature_bytes =
        match SignatureBytes::from_bytes(indexed_attestation.signature.as_bytes().as_slice()) {
            Ok(value) => value,
            Err(_) => return Err(Error::SignatureConversionError),
        };

    if verify_signature {
        let is_valid = match bls_verify(&pubkeys_bytes, &signing_root.as_bytes(), &signature_bytes)
        {
            Ok(value) => value,
            Err(_) => return Err(Error::InvalidSignature),
        };

        if !is_valid {
            return Err(Error::InvalidSignature);
        }
    }

    Ok(())
}

pub fn is_valid_merkle_branch(
    leaf: &H256,
    branch: &[H256],
    depth: u64,
    index: u64,
    root: &H256,
) -> Result<bool, Error> {
    let mut value: H256 = *leaf;
    match usize::try_from(depth) {
        Ok(depth_usize) => {
            for (i, node) in branch.iter().enumerate().take(depth_usize) {
                if index / (2 ^ (i as u64)) % 2 == 0 {
                    value = H256::from_slice(&hash(&join_hashes(&value, node)));
                } else {
                    value = H256::from_slice(&hash(&join_hashes(node, &value)));
                }
            }
            Ok(value == *root)
        }
        Err(_) => Err(Error::IndexOutOfRange),
    }
}

fn join_hashes<'a>(hash1: &'a H256, hash2: &H256) -> Vec<u8> {
    hash1
        .as_ref()
        .iter()
        .chain(hash2.as_ref())
        .copied()
        .collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::VariableList;
    use types::config::MainnetConfig;
    use types::types::Checkpoint;

    #[test]
    fn test_is_slashable_validator() {
        let v = Validator {
            slashed: false,
            activation_epoch: 0,
            withdrawable_epoch: 1,
            ..Validator::default()
        };
        assert_eq!(is_slashable_validator(&v, 0), true);
    }

    #[test]
    fn test_is_slashable_validator_already_slashed() {
        let v = Validator {
            slashed: true,
            activation_epoch: 0,
            withdrawable_epoch: 1,
            ..Validator::default()
        };
        assert_eq!(is_slashable_validator(&v, 0), false);
    }

    #[test]
    fn test_is_slashable_validator_activation_epoch_greater_than_epoch() {
        let v = Validator {
            slashed: false,
            activation_epoch: 1,
            withdrawable_epoch: 2,
            ..Validator::default()
        };
        assert_eq!(is_slashable_validator(&v, 0), false);
    }

    #[test]
    fn test_is_slashable_validator_withdrawable_epoch_equals_epoch() {
        let v = Validator {
            slashed: false,
            activation_epoch: 0,
            withdrawable_epoch: 1,
            ..Validator::default()
        };
        assert_eq!(is_slashable_validator(&v, 1), false);
    }

    #[test]
    fn test_is_active_validator() {
        let v = Validator {
            activation_epoch: 0,
            exit_epoch: 1,
            ..Validator::default()
        };
        assert_eq!(is_active_validator(&v, 0), true);
    }

    #[test]
    fn test_is_active_validator_activation_epoch_greater_than_epoch() {
        let v = Validator {
            activation_epoch: 1,
            exit_epoch: 2,
            ..Validator::default()
        };
        assert_eq!(is_active_validator(&v, 0), false);
    }

    #[test]
    fn test_is_active_validator_exit_epoch_equals_epoch() {
        let v = Validator {
            activation_epoch: 0,
            exit_epoch: 1,
            ..Validator::default()
        };
        assert_eq!(is_active_validator(&v, 1), false);
    }

    #[test]
    fn test_is_slashable_attestation_data_double_vote_false() {
        let attestation_data_1 = AttestationData {
            target: Checkpoint {
                epoch: 1,
                root: H256::from([0; 32]),
            },
            ..AttestationData::default()
        };
        let attestation_data_2 = AttestationData {
            target: Checkpoint {
                epoch: 1,
                root: H256::from([0; 32]),
            },
            ..AttestationData::default()
        };
        assert_eq!(
            is_slashable_attestation_data(&attestation_data_1, &attestation_data_2),
            false
        );
    }

    #[test]
    fn test_is_slashable_attestation_data_double_vote_true() {
        let attestation_data_1 = AttestationData {
            target: Checkpoint {
                epoch: 1,
                root: H256::from([0; 32]),
            },
            ..AttestationData::default()
        };
        let attestation_data_2 = AttestationData {
            target: Checkpoint {
                epoch: 1,
                root: H256::from([1; 32]),
            },
            ..AttestationData::default()
        };
        assert_eq!(
            is_slashable_attestation_data(&attestation_data_1, &attestation_data_2),
            true
        );
    }

    #[test]
    fn test_is_slashable_attestation_data_surround_vote_true() {
        let attestation_data_1 = AttestationData {
            source: Checkpoint {
                epoch: 0,
                root: H256::from([0; 32]),
            },
            target: Checkpoint {
                epoch: 3,
                root: H256::from([0; 32]),
            },
            ..AttestationData::default()
        };
        let attestation_data_2 = AttestationData {
            source: Checkpoint {
                epoch: 1,
                root: H256::from([1; 32]),
            },
            target: Checkpoint {
                epoch: 2,
                root: H256::from([0; 32]),
            },
            ..AttestationData::default()
        };
        assert_eq!(
            is_slashable_attestation_data(&attestation_data_1, &attestation_data_2),
            true
        );
    }

    #[test]
    fn test_is_valid_indexed_attestation_max_indices_exceeded() {
        let state: BeaconState<MainnetConfig> = BeaconState::<MainnetConfig>::default();
        let indices: Vec<u64> = (0_u64..4097_u64).collect();
        let attestation: IndexedAttestation<MainnetConfig> = IndexedAttestation {
            attesting_indices: VariableList::from(indices),
            ..IndexedAttestation::default()
        };
        assert_eq!(
            validate_indexed_attestation::<MainnetConfig>(&state, &attestation),
            Err(Error::IndicesExceedMaxValidators)
        );
    }

    #[test]
    fn test_is_valid_indexed_attestation_bad_validator_indices_ordering() {
        let state: BeaconState<MainnetConfig> = BeaconState::<MainnetConfig>::default();
        let indices = vec![66_u64, 65_u64];
        let attestation: IndexedAttestation<MainnetConfig> = IndexedAttestation {
            attesting_indices: VariableList::from(indices),
            ..IndexedAttestation::default()
        };
        assert_eq!(
            validate_indexed_attestation::<MainnetConfig>(&state, &attestation),
            Err(Error::IndicesNotSorted)
        );
    }
}
