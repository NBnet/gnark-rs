mod gnark;

use gnark::{GnarkVerifyCall, GnarkVerifyCallImpl};

pub fn gnark_groth16_verify(
    id: u16,
    proof: Vec<u8>,
    verify_key: Vec<u8>,
    witness: Vec<u8>,
) -> bool {
    return GnarkVerifyCallImpl::gnark_groth16_verify(id, proof, verify_key, witness);
}

pub fn gnark_plonk_verify(id: u16, proof: Vec<u8>, verify_key: Vec<u8>, witness: Vec<u8>) -> bool {
    return GnarkVerifyCallImpl::gnark_plonk_verify(id, proof, verify_key, witness);
}
