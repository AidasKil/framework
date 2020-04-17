mod cg_types;
mod cg_consts;

use anyhow::{ensure, Result};
use thiserror::Error;
use bls::Signature;
use types::primitives::{Epoch, ValidatorIndex};
use crate::cg_consts::{EPOCHS_PER_CUSTODY_PERIOD, CUSTODY_PERIOD_TO_RANDAO_PADDING};

fn main() {
    let slashing = cg_types::CustodySlashing{
        data_index: 0,
        malefactor_index: 0,
        whistleblower_index: 0,
        data: vec![0; 1024]
    };
}


//helpers
#[derive(Error, Debug)]
enum Error{
    #[error("Bad values passed to 'legendre_bit'")]
    BadArgsForLegendreBit
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
            let mut r = n % 8;
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

pub fn get_randao_epoch_for_custody_period(period: u64, validator_index: ValidatorIndex) -> Epoch {
    let next_period_start = (period + 1) * (EPOCHS_PER_CUSTODY_PERIOD) - validator_index % EPOCHS_PER_CUSTODY_PERIOD;
    let epoch = Epoch::from(next_period_start + CUSTODY_PERIOD_TO_RANDAO_PADDING);
    return epoch;
}

pub fn get_custody_period_for_validator(validator_index: ValidatorIndex, epoch: Epoch) -> u64{
    return (epoch + validator_index % EPOCHS_PER_CUSTODY_PERIOD) / EPOCHS_PER_CUSTODY_PERIOD;
}