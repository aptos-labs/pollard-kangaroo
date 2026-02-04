//! Precomputed tables for the BSGS algorithm.

pub enum PrecomputedTables {
    #[cfg(feature = "bsgs_table32")]
    Bsgs32,
}

#[cfg(feature = "bsgs_table32")]
pub const BSGS_32: &[u8] = include_bytes!("rsc/table_32");
