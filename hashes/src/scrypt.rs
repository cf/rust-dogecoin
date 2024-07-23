//! Scrypt implementation.
//!

use rust_scrypt::{scrypt, ScryptParams};

/// scrypt hash of dogecoin block
pub fn hash(block: &Vec<u8>) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];

    // Got here https://litecoin.info/index.php/Scrypt
    // N = 1024
    let params = ScryptParams::new(1024, 1, 1);
    scrypt(&block, &block, &params, &mut hash);
    // REVIEW : need to reverse it ?
    // hash.reverse();

    hash
}
