// Misc
pub const BLS12_381_Q: u64 = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787;
pub const BYTES_PER_CUSTODY_ATOM: u32 = 48;

// Configuration

// Time
pub const RANDAO_PENALTY_EPOCHS: u32 = 2**1;                            //12.8min
pub const EARLY_DERIVED_SECRET_PENALTY_MAX_FUTURE_EPOCHS: u32 = 2**14;  //~73days
pub const EPOCHS_PER_CUSTODY_PERIOD: u32 = 2**11;                       //~9days
pub const CUSTODY_PERIOD_TO_RANDAO_PADDING: u32 = 2*11;                 //~9days
pub const MAX_REVEAL_LATENESS_DECREMENT: u32 = 2**7;                    //~14hours

// Max Operations per block
pub const MAX_CUSTODY_KEY_REVEALS: u32 = 2**8;
pub const MAX_EARLY_DERIVED_SECRET_REVEALS: u32 = 1;
pub const MAX_CUSTODY_SLASHINGS: u32 = 1;

// Reward and penalty quotients
pub const EARLY_DERIVED_SECRET_REVEAL_SLOT_REWARD_MULTIPLE: u32 = 2**1;
pub const MINOR_REWARD_QUOTIENT: u32 = 2**8;