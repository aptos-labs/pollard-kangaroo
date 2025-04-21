use crate::kangaroo::Parameters;

pub enum Presets {
    #[cfg(feature = "table16")]
    Kangaroo16,
    #[cfg(feature = "table32")]
    Kangaroo32,
    #[cfg(feature = "table48")]
    Kangaroo48,
}

#[cfg(feature = "table16")]
pub const PARAMETERS_16: Parameters = Parameters {
    i: 8,
    W: 8,
    N: 8000,
    R: 64,
    secret_size: 16,
};

#[cfg(feature = "table32")]
pub const PARAMETERS_32: Parameters = Parameters {
    i: 8,
    W: 2048,
    N: 4000,
    R: 128,
    secret_size: 32,
};

#[cfg(feature = "table48")]
pub const PARAMETERS_48: Parameters = Parameters {
    i: 8,
    W: 65536,
    N: 40000,
    R: 128,
    secret_size: 48,
};

#[cfg(feature = "table16")]
pub const KANGAROO_16: &[u8] = include_bytes!("rsc/table_16");

#[cfg(feature = "table32")]
pub const KANGAROO_32: &[u8] = include_bytes!("rsc/table_32");

#[cfg(feature = "table48")]
pub const KANGAROO_48: &[u8] = include_bytes!("rsc/table_48");
