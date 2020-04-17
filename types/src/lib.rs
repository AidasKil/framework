// Lints are currently suppressed to prevent merge conflicts in case our contributors fix their code
// on their own. This attribute should be removed in the future.
#![allow(warnings)]

pub mod beacon_state;
pub mod config;
pub mod consts;
pub mod fixed_vector;
pub mod helper_functions_types;
pub mod primitives;
pub mod types;
pub mod custody_game_types;

pub use crate::beacon_state::{Error as BeaconStateError, *};

#[cfg(test)]
mod spec_tests {
    use core::fmt::Debug;

    use serde::{de::DeserializeOwned, Deserialize};
    use spec_test_utils::Case;
    use ssz_new::{SszDecode, SszEncode};
    use test_generator::test_resources;
    use tree_hash::TreeHash;

    use crate::{
        config::{MainnetConfig, MinimalConfig},
        primitives::H256,
    };

    mod tested_types {
        pub use crate::{beacon_state::BeaconState, types::*};
    }

    #[derive(Deserialize)]
    struct Roots {
        root: H256,
    }

    macro_rules! tests_for_type {
        (
            $type: ident $(<_ $bracket: tt)?,
            $mainnet_glob: literal,
            $minimal_glob: literal,
        ) => {
            mod $type {
                use super::*;

                #[test_resources($mainnet_glob)]
                fn mainnet(case: Case) {
                    run_case::<tested_types::$type$(<MainnetConfig $bracket)?>(case);
                }

                #[test_resources($minimal_glob)]
                fn minimal(case: Case) {
                    run_case::<tested_types::$type$(<MinimalConfig $bracket)?>(case);
                }
            }
        };
    }

    // We do not generate tests for `AggregateAndProof` and `Eth1Block`
    // because this crate does not have those yet.

    tests_for_type! {
        Attestation<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/Attestation/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/Attestation/*/*",
    }

    tests_for_type! {
        AttestationData,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/AttestationData/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/AttestationData/*/*",
    }

    tests_for_type! {
        AttesterSlashing<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/AttesterSlashing/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/AttesterSlashing/*/*",
    }

    tests_for_type! {
        BeaconBlock<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/BeaconBlock/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/BeaconBlock/*/*",
    }

    tests_for_type! {
        BeaconBlockBody<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/BeaconBlockBody/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/BeaconBlockBody/*/*",
    }

    tests_for_type! {
        BeaconBlockHeader,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/BeaconBlockHeader/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/BeaconBlockHeader/*/*",
    }

    tests_for_type! {
        BeaconState<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/BeaconState/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/BeaconState/*/*",
    }

    tests_for_type! {
        Checkpoint,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/Checkpoint/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/Checkpoint/*/*",
    }

    tests_for_type! {
        Deposit,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/Deposit/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/Deposit/*/*",
    }

    tests_for_type! {
        DepositData,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/DepositData/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/DepositData/*/*",
    }

    tests_for_type! {
        DepositMessage,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/DepositMessage/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/DepositMessage/*/*",
    }

    tests_for_type! {
        Eth1Data,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/Eth1Data/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/Eth1Data/*/*",
    }

    tests_for_type! {
        Fork,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/Fork/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/Fork/*/*",
    }

    tests_for_type! {
        HistoricalBatch<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/HistoricalBatch/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/HistoricalBatch/*/*",
    }

    tests_for_type! {
        IndexedAttestation<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/IndexedAttestation/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/IndexedAttestation/*/*",
    }

    tests_for_type! {
        PendingAttestation<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/PendingAttestation/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/PendingAttestation/*/*",
    }

    tests_for_type! {
        ProposerSlashing,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/ProposerSlashing/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/ProposerSlashing/*/*",
    }

    tests_for_type! {
        SignedBeaconBlock<_>,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/SignedBeaconBlock/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/SignedBeaconBlock/*/*",
    }

    tests_for_type! {
        SignedBeaconBlockHeader,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/SignedBeaconBlockHeader/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/SignedBeaconBlockHeader/*/*",
    }

    tests_for_type! {
        SignedVoluntaryExit,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/SignedVoluntaryExit/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/SignedVoluntaryExit/*/*",
    }

    tests_for_type! {
        SigningRoot,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/SigningRoot/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/SigningRoot/*/*",
    }

    tests_for_type! {
        Validator,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/Validator/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/Validator/*/*",
    }

    tests_for_type! {
        VoluntaryExit,
        "eth2.0-spec-tests/tests/mainnet/phase0/ssz_static/VoluntaryExit/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/ssz_static/VoluntaryExit/*/*",
    }

    fn run_case<D>(case: Case)
    where
        D: PartialEq + Debug + DeserializeOwned + SszDecode + SszEncode + TreeHash,
    {
        let ssz_bytes = case.bytes("serialized.ssz");
        let yaml_value = case.yaml("value");
        let Roots { root } = case.yaml("roots");

        let ssz_value = D::from_ssz_bytes(ssz_bytes.as_slice())
            .expect("the file should contain a value encoded in SSZ");

        assert_eq!(ssz_value, yaml_value);
        assert_eq!(ssz_bytes, yaml_value.as_ssz_bytes());
        assert_eq!(yaml_value.tree_hash_root(), root);
    }
}
