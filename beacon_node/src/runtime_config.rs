use anyhow::{ensure, Result};
use eth2_network_libp2p::NetworkConfig;
use serde::Deserialize;
use thiserror::Error;
use types::{
    config::{Config as _, MainnetConfig},
    primitives::{UnixSeconds, ValidatorIndex},
};

#[derive(Debug, Error)]
enum Error {
    #[error("missing executable path")]
    MissingExecutablePath,
    #[error("missing configuration")]
    MissingConfiguration,
    #[error("trailing arguments")]
    TrailingArguments,
}

#[derive(Deserialize)]
pub enum Preset {
    Mainnet,
    Minimal,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub preset: Preset,
    pub genesis_time: UnixSeconds,
    pub validator_count: ValidatorIndex,
    #[serde(flatten)]
    pub network: NetworkConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            preset: Preset::Mainnet,
            genesis_time: MainnetConfig::min_genesis_time(),
            validator_count: MainnetConfig::min_genesis_active_validator_count(),
            network: NetworkConfig::default(),
        }
    }
}

impl RuntimeConfig {
    pub fn parse(mut strings: impl ExactSizeIterator<Item = String>) -> Result<Self> {
        ensure!(strings.next().is_some(), Error::MissingExecutablePath);
        let first_argument = strings.next().ok_or(Error::MissingConfiguration)?;
        ensure!(strings.len() == 0, Error::TrailingArguments);
        let runtime_config = serde_yaml::from_str(first_argument.as_str())?;
        Ok(runtime_config)
    }
}

// There used to be tests here but we were forced to omit them to save time.
