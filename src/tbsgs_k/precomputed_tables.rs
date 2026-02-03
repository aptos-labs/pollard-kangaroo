//! Precomputed tables for the TBSGS-k algorithm.

pub enum PrecomputedTables {
    #[cfg(feature = "tbsgs_k_table32")]
    TbsgsK32,
}

#[cfg(feature = "tbsgs_k_table32")]
pub const TBSGS_K_32: &[u8] = include_bytes!("rsc/table_32");
