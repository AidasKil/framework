use bls::{
    AggregatePublicKey, AggregateSignature, PublicKey, PublicKeyBytes, Signature, SignatureBytes,
};

use ring::digest::{digest, SHA256};
use ssz_new::SszDecodeError;
use std::convert::TryInto;
use tree_hash::TreeHash;
use types::primitives::H256;

pub fn hash(input: &[u8]) -> Vec<u8> {
    digest(&SHA256, input).as_ref().into()
}

pub fn bls_verify(
    pubkey: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<bool, SszDecodeError> {
    let pk: PublicKey = pubkey.try_into()?;
    let sg: Signature = signature.try_into()?;

    Ok(sg.verify(message, &pk))
}

pub fn bls_verify_multiple(
    pubkeys: &[&PublicKeyBytes],
    messages: &[&[u8]],
    signature: &SignatureBytes,
) -> Result<bool, SszDecodeError> {
    let sg = AggregateSignature::from_bytes(signature.as_bytes().as_slice())?;

    let mut apk = AggregatePublicKey::new();
    for pkb in pubkeys {
        let pk = (*pkb).try_into()?;
        apk.add(&pk);
    }

    Ok(sg.verify_multiple(messages, &[&apk]))
}

pub fn bls_aggregate_pubkeys(pubkeys: &[PublicKey]) -> AggregatePublicKey {
    let mut aggr_pk = AggregatePublicKey::new();
    for pk in pubkeys {
        aggr_pk.add(pk);
    }
    aggr_pk
}

pub fn hash_tree_root<T: TreeHash>(object: &T) -> H256 {
    let hash = object.tree_hash_root();
    H256::from_slice(hash.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::SecretKey;
    use rustc_hex::FromHex;
    use types::types::AttestationData;

    #[test]
    fn test_hash() {
        let input: Vec<u8> = b"Hello World!!!".as_ref().into();

        let output = hash(&input);
        let expected_hex = "073F7397B078DCA7EFC7F9DC05B528AF1AFBF415D3CAA8A5041D1A4E5369E0B3";
        let expected: Vec<u8> = expected_hex
            .from_hex()
            .expect("Invalid hex string constant");
        assert_eq!(expected, output);
    }

    #[test]
    fn test_bls_verify_simple() {
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];

        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let pk = PublicKey::from_secret_key(&sk);
        let domain: u64 = 0;

        // Sign a message
        let message = b"cats";
        let signature = Signature::new(message, domain, &sk);
        assert!(signature.verify(message, domain, &pk));

        let pk_bytes =
            PublicKeyBytes::from_bytes(pk.as_bytes().as_slice()).expect("Expected success");
        let sg_bytes =
            SignatureBytes::from_bytes(signature.as_bytes().as_slice()).expect("Expected sucess");

        assert_eq!(bls_verify(&pk_bytes, message, &sg_bytes, domain), Ok(true));
    }

    #[test]
    fn test_bls_verify_fail() {
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];

        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let pk = PublicKey::from_secret_key(&sk);
        let domain: u64 = 0;

        // Sign a message
        let message = b"cats";
        let signature = Signature::new(message, domain, &sk);
        // Different domain
        assert!(!signature.verify(message, 1, &pk));

        let pk_bytes =
            PublicKeyBytes::from_bytes(pk.as_bytes().as_slice()).expect("Expected success");
        let sg_bytes =
            SignatureBytes::from_bytes(signature.as_bytes().as_slice()).expect("Expected sucess");

        // Different domain
        assert_eq!(bls_verify(&pk_bytes, message, &sg_bytes, 1), Ok(false));
    }

    #[test]
    fn test_bls_verify_invalid_pubkey() {
        // Create a valid signature first
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let domain: u64 = 0;
        // Sign a message
        let message = b"cats";
        let signature = Signature::new(message, domain, &sk);

        let pk_bytes = PublicKeyBytes::from_bytes(&[0; 48]).expect("Expected success");
        let sg_bytes =
            SignatureBytes::from_bytes(signature.as_bytes().as_slice()).expect("Expected success");

        // Different domain
        let err = SszDecodeError::BytesInvalid(format!("Invalid PublicKey bytes: {:?}", pk_bytes));
        assert_eq!(bls_verify(&pk_bytes, message, &sg_bytes, 1), Err(err));
    }

    #[test]
    fn test_verify_multiple() {
        let domain: u64 = 45;
        let msg_1: Vec<u8> = vec![111; 32];
        let msg_2: Vec<u8> = vec![222; 32];

        // To form first AggregatePublicKey (and sign messages)
        let mut aggregate_signature = AggregateSignature::new();
        let sk1 = SecretKey::random();
        let pk1 = PublicKey::from_secret_key(&sk1);
        aggregate_signature.add(&Signature::new(&msg_1, domain, &sk1));
        let sk2 = SecretKey::random();
        let pk2 = PublicKey::from_secret_key(&sk2);
        aggregate_signature.add(&Signature::new(&msg_1, domain, &sk2));
        let mut apk1 = AggregatePublicKey::new();
        apk1.add(&pk1);
        apk1.add(&pk2);
        // Verify with one AggregateSignature and Message (same functionality as AggregateSignature::verify())
        let apk1_bytes = PublicKeyBytes::from_bytes(apk1.as_raw().as_bytes().as_slice())
            .expect("Unexpected error");
        let sig_bytes = SignatureBytes::from_bytes(aggregate_signature.as_bytes().as_slice())
            .expect("Unexpected error");
        assert!(
            bls_verify_multiple(&[&apk1_bytes], &[msg_1.as_slice()], &sig_bytes, domain)
                .expect("Unexpected error")
        );

        let sk3 = SecretKey::random();
        let pk3 = PublicKey::from_secret_key(&sk3);
        aggregate_signature.add(&Signature::new(&msg_2, domain, &sk3));
        let sk4 = SecretKey::random();
        let pk4 = PublicKey::from_secret_key(&sk4);
        aggregate_signature.add(&Signature::new(&msg_2, domain, &sk4));
        let apk2 = bls_aggregate_pubkeys(&[pk3, pk4]);

        let apk2_bytes = PublicKeyBytes::from_bytes(apk2.as_raw().as_bytes().as_slice())
            .expect("Unexpected error");
        let sig_bytes = SignatureBytes::from_bytes(aggregate_signature.as_bytes().as_slice())
            .expect("Unexpected error");
        assert!(bls_verify_multiple(
            &[&apk1_bytes, &apk2_bytes],
            &[msg_1.as_slice(), msg_2.as_slice()],
            &sig_bytes,
            domain
        )
        .expect("Unexpected error"));
    }

    #[test]
    fn test_bls_verify_invalid_sig() {
        // Create a valid public key first
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let pk = PublicKey::from_secret_key(&sk);

        let pk_bytes =
            PublicKeyBytes::from_bytes(pk.as_bytes().as_slice()).expect("Expected success");
        let sg_bytes = SignatureBytes::from_bytes(&[1; 96]).expect("Expected success");

        // Different domain
        let err = SszDecodeError::BytesInvalid(format!("Invalid Signature bytes: {:?}", sg_bytes));
        assert_eq!(bls_verify(&pk_bytes, b"aaabbb", &sg_bytes, 1), Err(err));
    }

    #[test]
    fn test_hash_tree_root() {
        let obj = AttestationData::default();
        let hash: H256 = H256::from_slice(obj.tree_hash_root().as_slice());
        let hash2 = hash_tree_root(&obj);
        assert_eq!(hash, hash2);
    }
}
