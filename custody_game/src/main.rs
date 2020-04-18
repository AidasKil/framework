mod cg_consts;

use anyhow::{ensure, Result};
use thiserror::Error;
use bls::Signature;
use types::primitives::{Epoch, ValidatorIndex, H256};
use crate::cg_consts::{EPOCHS_PER_CUSTODY_PERIOD, CUSTODY_PERIOD_TO_RANDAO_PADDING, MAX_REVEAL_LATENESS_DECREMENT};
use types::BeaconState;
use types::config::Config;
use types::types::{BeaconBlockBody, Validator};
use types::custody_game_types::{CustodyKeyReveal, CustodySlashing};
use helper_functions::beacon_state_accessors;
use helper_functions::beacon_state_mutators;
use helper_functions::beacon_state_accessors::get_current_epoch;
use helper_functions::predicates::{ is_slashable_validator };
use helper_functions::misc::{ compute_signing_root };
use helper_functions::crypto::bls_verify;

fn main() {
    /*let slashing = CustodySlashing{
        data_index: 0,
        malefactor_index: 0,
        whistleblower_index: 0,
        data: vec![0; 1024]
    };*/
}


//helpers
#[derive(Error, Debug)]
enum Error{
    #[error("Bad values passed to 'legendre_bit'")]
    BadArgsForLegendreBit,
    #[error("Revealing custody secret too early")]
    RevealingCustodySecretTooEarly,
    #[error("Can't slash the custody key revealer")]
    UnslashableCustodyKeyRevealer
}

pub fn legendre_bit(a: i32, q: i32) -> Result<i32> {
    if a >= q {
        return legendre_bit(a % q, q);
    }
    if a == 0 {
        return Ok(0);
    }
    ensure!((q > a) && (a > 0) && q % 2 == 1, Error::BadArgsForLegendreBit);

    let mut t: i32 = 1;
    let mut n: i32 = q;
    let mut m: i32 = a;
    while m != 0 {
        while m % 2 == 0 {
            m = m / 2;
            let r = n % 8;
            if r == 3 || r == 5 {
                t = -t;
            }
        }
        let temp = m;
        m = n;
        n = temp;
        if (m % 4 == n % 4) && (m % 4 == 3 && n % 4 == 3) {
            t = -t;
        }
        m %= n;
    }
    if n == 1 {
        return Ok((t + 1) / 2);
    }
    return Ok(0);
}

pub fn get_custody_atoms(bytes: &Vec<u8>) -> Result<Vec<u8>>{
    let to_pad = cg_consts::BYTES_PER_CUSTODY_ATOM as usize -  bytes.len();
    let padding = vec![0 as u8; to_pad];

    let mut result = bytes.to_vec();
    result.extend(padding);
    return Ok(result);
}

//TODO G2, also possible change of spec as per https://github.com/ethereum/eth2.0-specs/pull/1705/commits/ca6af0c2e9bfba1667ea7b6a67a03144be7aa23b
pub fn compute_custody_bit(key: Signature, bytes: &Vec<u8>) -> Result<u8> {
    //TODO:
    //full_G2_element = bls.signature_to_G2(key)
    //s = full_G2_element[0].coeffs
    let atoms = get_custody_atoms(bytes)?;
    for (i, val) in atoms.iter().enumerate(){

    }

    return Ok(1);
}


//per-block processing

//TODO:
/*pub fn process_custody_game_operations<C: Config>(state: &BeaconState<C>, body: &BeaconBlockBody<C>) -> Result<()> {
    for reveal in body.custody_key_reveals {
        process_custody_key_reveal(reveal);
    }
    for reveal in body.early_derived_secret_reveals {
        process_early_derived_secret_reveal(reveal);
    }
    for slashing in body.custody_slashings {
        process_custody_slashing(slashing);
    }
    return Ok(());
}*/
