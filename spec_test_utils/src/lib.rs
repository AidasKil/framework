use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use ethereum_types::H256;
use serde::{de::DeserializeOwned, Deserialize};
use serde_repr::Deserialize_repr;
use ssz_new::SszDecode;

#[derive(Deserialize_repr)]
#[repr(u8)]
enum BlsSetting {
    Optional = 0,
    Required = 1,
    Ignored = 2,
}

#[derive(Deserialize)]
struct SharedMeta {
    bls_setting: Option<BlsSetting>,
}

#[derive(Deserialize)]
struct BlocksMeta {
    blocks_count: usize,
}

#[derive(Deserialize)]
struct Roots {
    root: H256,
}

pub fn bls_setting(case_directory: impl AsRef<Path>) -> Option<bool> {
    yaml(resolve(case_directory).join("meta.yaml"))
        .and_then(|meta: SharedMeta| meta.bls_setting)
        .and_then(|bls_setting| match bls_setting {
            BlsSetting::Optional => None,
            BlsSetting::Required => Some(true),
            BlsSetting::Ignored => Some(false),
        })
}

pub fn pre<D: SszDecode>(case_directory: impl AsRef<Path>) -> D {
    ssz(resolve(case_directory).join("pre.ssz"))
        .expect("every state transition test should have a pre-state")
}

pub fn post<D: SszDecode>(case_directory: impl AsRef<Path>) -> Option<D> {
    ssz(resolve(case_directory).join("post.ssz"))
}

pub fn slots(case_directory: impl AsRef<Path>) -> u64 {
    yaml(resolve(case_directory).join("slots.yaml"))
        .expect("every slot sanity test should specify the number of slots")
}

pub fn blocks<D: SszDecode>(case_directory: impl AsRef<Path>) -> impl Iterator<Item = D> {
    let BlocksMeta { blocks_count } = yaml(resolve(&case_directory).join("meta.yaml"))
        .expect("every block sanity test should specify the number of blocks");
    (0..blocks_count).map(move |index| {
        let file_name = format!("blocks_{}.ssz", index);
        ssz(resolve(&case_directory).join(file_name))
            .expect("block sanity tests should have the number of blocks they claim to have")
    })
}

pub fn operation<D: SszDecode>(
    case_directory: impl AsRef<Path>,
    operation_name: impl AsRef<Path>,
) -> D {
    let operation_path = resolve(case_directory)
        .join(operation_name)
        .with_extension("ssz");
    ssz(operation_path).expect("every operation test should have a file representing the operation")
}

pub fn serialized(case_directory: impl AsRef<Path>) -> Vec<u8> {
    read_optional(resolve(case_directory).join("serialized.ssz"))
        .expect("every SSZ test should have a file with the value encoded in SSZ")
}

pub fn value<D: DeserializeOwned>(case_directory: impl AsRef<Path>) -> D {
    yaml(resolve(case_directory).join("value.yaml"))
        .expect("every SSZ test should have a file with the value encoded in YAML")
}

pub fn hash_tree_root(case_directory: impl AsRef<Path>) -> H256 {
    let Roots { root } = yaml(resolve(case_directory).join("roots.yaml"))
        .expect("every SSZ test should specify the root of the value");
    root
}

fn resolve(case_directory_relative_to_repository_root: impl AsRef<Path>) -> PathBuf {
    // Cargo appears to set the working directory to the crate root when running tests.
    PathBuf::from("..").join(case_directory_relative_to_repository_root)
}

fn ssz<D: SszDecode>(file_path: impl AsRef<Path>) -> Option<D> {
    let bytes = read_optional(file_path)?;
    let value = D::from_ssz_bytes(bytes.as_slice())
        .expect("the file should contain a value encoded in SSZ");
    Some(value)
}

fn yaml<D: DeserializeOwned>(file_path: impl AsRef<Path>) -> Option<D> {
    let bytes = read_optional(file_path)?;
    let value = serde_yaml::from_slice(bytes.as_slice())
        .expect("the file should contain a value encoded in YAML");
    Some(value)
}

fn read_optional(file_path: impl AsRef<Path>) -> Option<Vec<u8>> {
    match std::fs::read(file_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => panic!("could not read the file: {:?}", error),
    }
}
