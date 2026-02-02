//! Precomputed tables for the BL12 algorithm.

pub enum PrecomputedTables {
    #[cfg(feature = "bl12_table32")]
    BernsteinLange32,
}

#[cfg(feature = "bl12_table32")]
pub const BL12_32: &[u8] = include_bytes!("rsc/table_32");
