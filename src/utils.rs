use anyhow::{Context, Result};
use core::ops::Mul;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};

/// Generates a random scalar with the specified number of bits.
pub fn generate_random_scalar(bits: u8) -> Result<Scalar> {
    if bits > 64 {
        return Err(anyhow::anyhow!("bits must be less than or equal to 64"));
    }

    let mut key = [0u8; 32];

    let last_byte = ((bits + 7) >> 3) as usize;
    OsRng.fill_bytes(&mut key[..last_byte]);

    if bits & 0x07 != 0 {
        key[last_byte - 1] &= (1 << (bits & 0x07)) - 1;
    }

    Option::from(Scalar::from_canonical_bytes(key)).context("failed to construct scalar")
}

/// Converts a scalar to an u64.
pub fn scalar_to_u64(scalar: &Scalar) -> u64 {
    let (u64_bytes, _) = scalar.as_bytes().split_at(size_of::<u64>());

    u64::from_le_bytes(u64_bytes.try_into().unwrap())
}

/// Converts a u64 to a scalar.
pub fn u64_to_scalar(value: u64) -> Scalar {
    Scalar::from(value)
}

/// Generates a random scalar and its corresponding "public key".
pub fn generate_keypair(bits: u8) -> Result<(Scalar, RistrettoPoint)> {
    let sk = generate_random_scalar(bits).context("failed to generate secret")?;

    Ok((sk, RISTRETTO_BASEPOINT_POINT.mul(sk)))
}
