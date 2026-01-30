use super::BsgsKParameters;

pub enum BsgsKPresets {
    #[cfg(feature = "bsgs_k_table32")]
    BabyGiantK32,
}

#[cfg(feature = "bsgs_k_table32")]
pub const PARAMETERS_32: BsgsKParameters = BsgsKParameters {
    secret_size: 32,
    // m = ceil(sqrt(2^32)) = 2^16 = 65536
    m: 65536,
};

#[cfg(feature = "bsgs_k_table32")]
pub const BSGS_K_32: &[u8] = include_bytes!("rsc/table_32");
