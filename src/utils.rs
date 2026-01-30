use anyhow::{Context, Result};
use core::ops::Mul;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{OsRng, RngCore};

/// Generates a random scalar with the specified number of bits.
/// The returned scalar will be in the range [0, 2^bits).
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

/// Converts a scalar to a u64. Only valid for scalars < 2^64.
pub fn scalar_to_u64(scalar: &Scalar) -> u64 {
    let (u64_bytes, _) = scalar.as_bytes().split_at(size_of::<u64>());

    u64::from_le_bytes(u64_bytes.try_into().unwrap())
}

/// Converts a u64 to a scalar.
pub fn u64_to_scalar(value: u64) -> Scalar {
    Scalar::from(value)
}

/// Generates a random discrete log instance: a scalar x and the point g^x.
pub fn generate_dlog_instance(bits: u8) -> Result<(Scalar, RistrettoPoint)> {
    let sk = generate_random_scalar(bits).context("failed to generate secret")?;

    Ok((sk, RISTRETTO_BASEPOINT_POINT.mul(sk)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_scalar_bounds() {
        // Test various bit sizes
        for bits in 1..=64 {
            let max_value = if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };

            // Generate multiple samples to increase confidence
            for _ in 0..100 {
                let scalar = generate_random_scalar(bits).unwrap();
                let value = scalar_to_u64(&scalar);

                assert!(
                    value <= max_value,
                    "generate_random_scalar({}) produced value {} which exceeds max {}",
                    bits,
                    value,
                    max_value
                );
            }
        }
    }

    #[test]
    fn test_generate_random_scalar_zero_bits_edge_case() {
        // 0 bits should produce 0
        // Actually, looking at the code, bits=0 would set last_byte=0,
        // so no bytes are filled, resulting in scalar 0
        let scalar = generate_random_scalar(0).unwrap();
        assert_eq!(scalar_to_u64(&scalar), 0);
    }

    #[test]
    fn test_scalar_to_u64_roundtrip() {
        // Test that u64_to_scalar and scalar_to_u64 are inverses
        let test_values: Vec<u64> = vec![
            0,
            1,
            42,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];

        for value in test_values {
            let scalar = u64_to_scalar(value);
            let recovered = scalar_to_u64(&scalar);
            assert_eq!(
                value, recovered,
                "Roundtrip failed for value {}: got {}",
                value, recovered
            );
        }
    }

    #[test]
    fn test_generate_random_scalar_rejects_large_bits() {
        // bits > 64 should fail
        assert!(generate_random_scalar(65).is_err());
        assert!(generate_random_scalar(128).is_err());
    }
}
