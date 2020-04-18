use crate::primitives::*;

pub use crate::primitives::Gwei;

pub const BASE_REWARDS_PER_EPOCH: u64 = 4;
pub const GENESIS_EPOCH: Epoch = 0;
pub const GENESIS_SLOT: Slot = 0;
pub const JUSTIFICATION_BITS_LENGTH: usize = 4;
pub const SECONDS_PER_DAY: u64 = 86400;
pub const FAR_FUTURE_EPOCH: u64 = u64::max_value(); // prideta
pub type DepositContractTreeDepth = typenum::U32;
pub type JustificationBitsLength = typenum::U4;

//duplicate of config::EarlyDerivedSecretPenaltyMaxFutureEpochs
pub const EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS: u64 = 16384;
//duplicate of config::SlotsPerEpoch
pub const SLOTS_PER_EPOCH: u64 = 32;

// Misc
pub static BLS12_381_Q: &str = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787";
pub const BYTES_PER_CUSTODY_ATOM: i32 = 48;

pub const DOMAIN_CUSTODY_BIT_SLASHING: DomainType = 6;

// Configuration

// Time
pub const RANDAO_PENALTY_EPOCHS: u64 = 2;                            //12.8min
pub const EPOCHS_PER_CUSTODY_PERIOD: u64 = 2048;                       //~9days
pub const CUSTODY_PERIOD_TO_RANDAO_PADDING: u64 = 2048;                 //~9days
pub const MAX_REVEAL_LATENESS_DECREMENT: u64 = 128;                    //~14hours

// Reward and penalty quotients
pub const EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE: u64 = 2;
pub const MINOR_REWARD_QUOTIENT: u64 = 256;
