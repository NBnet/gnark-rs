pub mod binding {
    #![allow(warnings)]
    rust2go::r2g_include_binding!();
}

#[rust2go::r2g]
pub trait GnarkVerifyCall {
    fn gnark_groth16_verify(id: u16, proof: Vec<u8>, verify_key: Vec<u8>, witness: Vec<u8>)
        -> bool;

    fn gnark_plonk_verify(id: u16, proof: Vec<u8>, verify_key: Vec<u8>, witness: Vec<u8>) -> bool;
}
