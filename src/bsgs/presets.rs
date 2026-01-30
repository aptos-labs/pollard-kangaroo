use crate::bsgs::BsgsParameters;

pub enum BsgsPresets {
    #[cfg(feature = "bsgs_table32")]
    BabyGiant32,
}

#[cfg(feature = "bsgs_table32")]
pub const PARAMETERS_32: BsgsParameters = BsgsParameters {
    secret_size: 32,
    // m = ceil(sqrt(2^32)) = 2^16 = 65536
    m: 65536,
};

#[cfg(feature = "bsgs_table32")]
pub const BSGS_32: &[u8] = include_bytes!("rsc/table_32");
