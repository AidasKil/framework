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
) -> Result<bool, SszDecodeError> {
    let public_key: PublicKey = pubkey.try_into()?;
    let signature: Signature = signature.try_into()?;

    Ok(signature.verify(message, &public_key))
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
    let hash: &[u8; 32] = hash_root[0..32]
        .try_into()
        .expect("Incorrect Tree Hash Root");
    H256::from_slice(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::SecretKey;

    #[test]
    fn test_hashing() {
        let input = b"lorem ipsum";
        let output = hash(input.as_ref());
        let output_bytes = output.as_ref();

        let expected_bytes = [
            0x5e, 0x2b, 0xf5, 0x7d, 0x3f, 0x40, 0xc4, 0xb6, 0xdf, 0x69, 0xda, 0xf1, 0x93, 0x6c,
            0xb7, 0x66, 0xf8, 0x32, 0x37, 0x4b, 0x4f, 0xc0, 0x25, 0x9a, 0x7c, 0xbf, 0xf0, 0x6e,
            0x2f, 0x70, 0xf2, 0x69,
        ];

        assert_eq!(expected_bytes, output_bytes);
    }

    #[test]
    #[allow(clippy::result_unwrap_used)]
    fn test_bls_verify() {
        // https://github.com/sigp/milagro_bls#single-signatures
        let secret_key = SecretKey::from_bytes(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x3e, 0x6a, 0x4c, 0x7d, 0xae, 0x8f, 0x35, 0x63, 0xfa, 0xbb, 0x9b, 0x57,
            0xd0, 0x4b, 0x4b, 0x21, 0xd3, 0xf2, 0xb9, 0xf4, 0x54, 0x4a, 0xdc, 0x7b, 0xed, 0xc6,
            0xcb, 0xb3, 0x6f, 0x03, 0x6b, 0x10,
        ])
        .unwrap();
        let public_key = PublicKey::from_secret_key(&secret_key);

        let msg_string = String::from("test123");
        let message = msg_string.as_bytes();
        let domain: Domain = 2;
        let signature = Signature::new(message, domain, &secret_key);

        let pk_bytes = PublicKeyBytes::from_bytes(&public_key.as_bytes()).unwrap();
        let sg_bytes = SignatureBytes::from_bytes(&signature.as_bytes()).unwrap();

        assert_eq!(bls_verify(&pk_bytes, message, &sg_bytes, domain), Ok(true));
    }

    #[test]
    fn test_bls_aggregate_pubkeys() {
        assert_eq!(
            bls_aggregate_pubkeys(&[]).as_raw(),
            AggregatePublicKey::new().as_raw()
        );
    }
}
