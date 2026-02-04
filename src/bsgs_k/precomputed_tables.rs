//! Precomputed tables for the BSGS-k algorithm.

pub enum PrecomputedTables {
    #[cfg(feature = "bsgs_k_table32")]
    BsgsK32,
}

#[cfg(feature = "bsgs_k_table32")]
pub const BSGS_K_32: &[u8] = include_bytes!("rsc/table_32");
