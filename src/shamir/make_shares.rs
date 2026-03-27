use super::ReconError;
use super::make_prime;
use super::uint_to_nz_uint;
use crypto_bigint::{NonZero, U512};
use rand::random;
/// Public function to expose splitting functionality
pub fn shamir_split(
    threshold: NonZero<u8>,
    shares: NonZero<u8>,
    secret: &U512,
) -> Result<Vec<(u8, U512)>, ReconError> {
    let prime = make_prime();
    let coeffs = gen_polynomial(secret, threshold.get(), &prime);
    let mut result: Vec<(u8, U512)> = Vec::new();
    for i in 1..=shares.get() {
        result.push((i, compute_poly(coeffs.as_slice(), i, &prime)?));
    }
    Ok(result)
}
/// Generates a random degree-n polynomial for Shamir's Secret Sharing
fn gen_polynomial(secret: &U512, degree: u8, prime: &U512) -> Vec<U512> {
    let mut coefficients: Vec<U512> = Vec::with_capacity(degree as usize);
    coefficients.push(*secret);
    for _ in 0..degree - 1 {
        coefficients.push(U512::from_be_slice(&random::<[u8; 64]>()) % *prime);
    }
    coefficients
}
/// Computes any given polynomial
fn compute_poly(coefficients: &[U512], x: u8, prime: &U512) -> Result<U512, ReconError> {
    let mut result = U512::ZERO;

    let x = U512::from_u8(x);
    for coefficient in coefficients.iter().rev() {
        result = (result * x).add_mod(coefficient, &uint_to_nz_uint(prime)?);
    }
    Ok(result)
}
