use core::fmt::Display;
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use serde::{de::DeserializeOwned, Deserialize};
use serde_repr::Deserialize_repr;
use ssz_new::SszDecode;

#[derive(PartialEq, Eq, Deserialize_repr)]
#[repr(u8)]
pub enum BlsSetting {
    Optional = 0,
    Required = 1,
    Ignored = 2,
}

impl Default for BlsSetting {
    fn default() -> Self {
        Self::Optional
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Meta {
    pub bls_setting: BlsSetting,
    pub blocks_count: usize,
    pub deposits_count: usize,
}

#[derive(Clone, Copy)]
pub struct Case<'d> {
    case_directory_relative_to_repository_root: &'d str,
}

impl<'d> From<&'d str> for Case<'d> {
    fn from(case_directory_relative_to_repository_root: &'d str) -> Self {
        Self {
            case_directory_relative_to_repository_root,
        }
    }
}

impl Case<'_> {
    #[must_use]
    pub fn meta(self) -> Meta {
        self.try_yaml("meta").unwrap_or_default()
    }

    pub fn iterator<'a, D: SszDecode>(
        &'a self,
        object_name: impl Display + 'a,
        object_count: usize,
    ) -> impl Iterator<Item = D> + 'a {
        (0..object_count).map(move |index| self.ssz(format!("{}_{}", object_name, index)))
    }

    pub fn bytes(self, file_name: impl AsRef<Path>) -> Vec<u8> {
        try_read(self.resolve().join(file_name)).expect("the file should exist")
    }

    pub fn ssz<D: SszDecode>(self, file_name: impl AsRef<Path>) -> D {
        self.try_ssz(file_name).expect("the SSZ file should exist")
    }

    pub fn try_ssz<D: SszDecode>(self, file_name: impl AsRef<Path>) -> Option<D> {
        let file_path = self.resolve().join(file_name).with_extension("ssz");
        let bytes = try_read(file_path)?;
        let value = D::from_ssz_bytes(bytes.as_slice())
            .expect("the file should contain a value encoded in SSZ");
        Some(value)
    }

    pub fn yaml<D: DeserializeOwned>(self, file_name: impl AsRef<Path>) -> D {
        self.try_yaml(file_name)
            .expect("the YAML file should exist")
    }

    fn try_yaml<D: DeserializeOwned>(self, file_name: impl AsRef<Path>) -> Option<D> {
        let file_path = self.resolve().join(file_name).with_extension("yaml");
        let bytes = try_read(file_path)?;
        let value = serde_yaml::from_slice(bytes.as_slice())
            .expect("the file should contain a value encoded in YAML");
        Some(value)
    }

    fn resolve(self) -> PathBuf {
        // Cargo appears to set the working directory to the crate root when running tests.
        PathBuf::from("..").join(self.case_directory_relative_to_repository_root)
    }
}

fn try_read(file_path: impl AsRef<Path>) -> Option<Vec<u8>> {
    match std::fs::read(file_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => panic!("could not read the file: {:?}", error),
    }
}
