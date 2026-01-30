//! Precomputed tables for the naive lookup algorithm.

/// Available precomputed tables for naive lookup.
pub enum PrecomputedTables {
    /// 16-bit table: can solve DLog for values in [0, 2^16).
    /// Table contains 65536 entries.
    #[cfg(feature = "naive_lookup_table16")]
    NaiveLookup16,
}

/// Precomputed table bytes for 16-bit secrets.
#[cfg(feature = "naive_lookup_table16")]
pub const NAIVE_LOOKUP_16: &[u8] = include_bytes!("../../tables/naive_lookup_16.bin");
