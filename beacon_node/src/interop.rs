use core::convert::TryInto as _;

use anyhow::Result;
use bls::{Keypair, PublicKey, SecretKey, Signature, BLS_SECRET_KEY_BYTE_SIZE};
use helper_functions::misc;
use hex_literal::hex;
use num_bigint::BigUint;
use typenum::Unsigned as _;
use types::{
    beacon_state::BeaconState,
    config::Config,
    primitives::{Epoch, UnixSeconds, ValidatorIndex, H256},
    types::{Deposit, DepositData, DepositMessage, Eth1Data},
};

use crate::{deposit_tree::DepositTree, genesis, hashing};

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#create-genesis-state>
const QUICK_START_ETH1_BLOCK_HASH: H256 = H256([0x42; 32]);

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#create-genesis-state>
///
/// This is defined in the standard but effectively never used because the genesis time derived from
/// this is replaced by the one passed in as a parameter.
const QUICK_START_ETH1_BLOCK_TIMESTAMP: UnixSeconds = 1 << 40;

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#pubkeyprivkey-generation>
///
/// Encoded in binary to avoid parsing a decimal string at runtime.
const CURVE_ORDER: &[u8] =
    &hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#quick-start-genesis>
pub fn quick_start_state<C: Config>(
    genesis_time: UnixSeconds,
    validator_count: ValidatorIndex,
) -> Result<BeaconState<C>> {
    let mut deposit_tree = DepositTree::default();

    let deposits = keypairs()
        .take(validator_count.try_into()?)
        .map(quick_start_deposit_data::<C>)
        .map(|data| {
            let (proof, _) = deposit_tree.add_deposit(&data)?;
            Ok(Deposit { proof, data })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut genesis_state = genesis::state(
        QUICK_START_ETH1_BLOCK_HASH,
        QUICK_START_ETH1_BLOCK_TIMESTAMP,
        deposits.as_slice(),
    )?;

    genesis_state.genesis_time = genesis_time;

    genesis::validate_state(&genesis_state)?;

    Ok(genesis_state)
}

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_eth1data#stub-standard>
pub fn eth1_data_stub<C: Config>(state: &BeaconState<C>, current_epoch: Epoch) -> Eth1Data {
    let epochs_per_period = C::SlotsPerEth1VotingPeriod::U64 / C::SlotsPerEpoch::U64;
    let voting_period = current_epoch / epochs_per_period;
    let deposit_root = hashing::hash(hashing::hash_from_u64(voting_period));
    Eth1Data {
        deposit_root,
        deposit_count: state.eth1_deposit_index,
        block_hash: hashing::hash(deposit_root),
    }
}

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#pubkeyprivkey-generation>
fn keypairs() -> impl Iterator<Item = Keypair> {
    let curve_order = BigUint::from_bytes_be(CURVE_ORDER);

    (0_usize..).map(move |index| {
        let index_hash = hashing::hash(hashing::hash_from_u64(index as ValidatorIndex));

        let sk_uint = BigUint::from_bytes_le(index_hash.as_bytes()) % &curve_order;

        let sk = SecretKey::from_bytes(&pad_to_secret_key_length(sk_uint.to_bytes_be()))
            .expect("the algorithm given in the standard should produce valid secret keys");

        let pk = PublicKey::from_secret_key(&sk);

        Keypair { sk, pk }
    })
}

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#generate-deposits>
fn quick_start_deposit_data<C: Config>(keypair: Keypair) -> DepositData {
    let mut withdrawal_credentials = hashing::hash(keypair.pk.as_bytes());
    withdrawal_credentials.as_mut()[0] = C::bls_withdrawal_prefix_byte();

    let deposit_message = DepositMessage {
        pubkey: keypair.pk.into(),
        withdrawal_credentials,
        amount: C::max_effective_balance(),
    };

    let domain = misc::compute_domain::<C>(C::domain_deposit(), None);
    let signing_root = misc::compute_signing_root(&deposit_message, domain);
    let signature = Signature::new(signing_root.as_bytes(), &keypair.sk).into();

    let DepositMessage {
        pubkey,
        withdrawal_credentials,
        amount,
    } = deposit_message;

    DepositData {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
    }
}

fn pad_to_secret_key_length(bytes: impl AsRef<[u8]>) -> [u8; BLS_SECRET_KEY_BYTE_SIZE] {
    let bytes = bytes.as_ref();
    let mut padded = [0; BLS_SECRET_KEY_BYTE_SIZE];
    padded[BLS_SECRET_KEY_BYTE_SIZE - bytes.len()..].copy_from_slice(bytes);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_order_matches_standard() {
        assert_eq!(
            BigUint::from_bytes_be(CURVE_ORDER).to_string(),
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
        );
    }

    // See the following:
    // - <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#test-vectors>
    // - <https://github.com/ethereum/eth2.0-pm/blob/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start/keygen_10_validators.yaml>
    #[test]
    fn keypairs_match_standard() {
        let expected_keypairs = [
            (
                hex!("25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"),
                hex!("a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
            ),
            (
                hex!("51d0b65185db6989ab0b560d6deed19c7ead0e24b9b6372cbecb1f26bdfad000"),
                hex!("b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
            ),
            (
                hex!("315ed405fafe339603932eebe8dbfd650ce5dafa561f6928664c75db85f97857"),
                hex!("a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
            ),
            (
                hex!("25b1166a43c109cb330af8945d364722757c65ed2bfed5444b5a2f057f82d391"),
                hex!("88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e"),
            ),
            (
                hex!("3f5615898238c4c4f906b507ee917e9ea1bb69b93f1dbd11a34d229c3b06784b"),
                hex!("81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e"),
            ),
            (
                hex!("055794614bc85ed5436c1f5cab586aab6ca84835788621091f4f3b813761e7a8"),
                hex!("ab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34"),
            ),
            (
                hex!("1023c68852075965e0f7352dee3f76a84a83e7582c181c10179936c6d6348893"),
                hex!("9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373"),
            ),
            (
                hex!("3a941600dc41e5d20e818473b817a28507c23cdfdb4b659c15461ee5c71e41f5"),
                hex!("a8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac"),
            ),
            (
                hex!("066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06"),
                hex!("a6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7"),
            ),
            (
                hex!("2b3b88a041168a1c4cd04bdd8de7964fd35238f95442dc678514f9dadb81ec34"),
                hex!("9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a"),
            ),
        ]
        .iter()
        .map(|(sk_bytes, pk_bytes)| Keypair {
            sk: SecretKey::from_bytes(&pad_to_secret_key_length(sk_bytes))
                .expect("every secret key given in the standard should be valid"),
            pk: PublicKey::from_bytes(pk_bytes)
                .expect("every public key given in the standard should be valid"),
        });

        assert!(keypairs().take(10).eq(expected_keypairs));
    }
}
