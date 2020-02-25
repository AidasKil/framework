use bls::{AggregatePublicKey, PublicKey, PublicKeyBytes, Signature, SignatureBytes};
use ring::digest::{digest, SHA256};
use ssz_new::SszDecodeError;
use std::convert::TryInto;
use tree_hash::TreeHash;
use types::primitives::*;

pub fn hash(input: &[u8]) -> Vec<u8> {
    digest(&SHA256, input).as_ref().to_vec()
}

pub fn bls_verify(
    pubkey: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
    domain: Domain,
) -> Result<bool, SszDecodeError> {
    let public_key: PublicKey = pubkey.try_into()?;
    let signature: Signature = signature.try_into()?;

    Ok(signature.verify(message, domain, &public_key))
}

pub fn bls_aggregate_pubkeys(pubkeys: &[PublicKey]) -> AggregatePublicKey {
    let mut aggregated = AggregatePublicKey::new();
    for pubkey in pubkeys {
        aggregated.add(pubkey);
    }
    aggregated
}

pub fn hash_tree_root<T: TreeHash>(object: &T) -> H256 {
    let hash_root = object.tree_hash_root();
    let hash: &[u8; 32] = hash_root[1..32]
        .try_into()
        .expect("Incorrect Tree Hash Root");
    H256::from_slice(hash)
}
