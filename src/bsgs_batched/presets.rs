use crate::bsgs_batched::BsgsBatchedParameters;

pub enum BsgsBatchedPresets {
    #[cfg(feature = "bsgs_batched_table32")]
    BabyGiantBatched32,
}

#[cfg(feature = "bsgs_batched_table32")]
pub const PARAMETERS_32: BsgsBatchedParameters = BsgsBatchedParameters {
    secret_size: 32,
    // m = ceil(sqrt(2^32)) = 2^16 = 65536
    m: 65536,
};

#[cfg(feature = "bsgs_batched_table32")]
pub const BSGS_BATCHED_32: &[u8] = include_bytes!("rsc/table_32");
