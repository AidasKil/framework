use derive_more::From;
use ssz_new::SszDecodeError;

#[derive(PartialEq, Debug, From)]
pub enum Error {
    SlotOutOfRange,
    IndexOutOfRange,
    IndicesNotSorted,
    IndicesExceedMaxValidators,
    InvalidSignature,
    NumberExceedsCapacity,
    ArrayIsEmpty,
    NotAHash,

    AttestationBitsInvalid,
    ConversionToUsize,
    ValidatorExitAlreadyInitiated,
    PubKeyConversionError,
    SignatureConversionError,

    SszDecode(SszDecodeError),
    BadArgsForLegendreBit,
}
