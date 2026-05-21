use super::Coeffs;
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
    let coeffs = gen_polynomial(secret, threshold.get() - 1, &prime);
    let mut result: Vec<(u8, U512)> = Vec::new();
    for i in 1..=shares.get() {
        result.push((i, compute_poly(&coeffs, i, &prime)?));
    }
    Ok(result)
}
/// Generates a random degree-n polynomial for Shamir's Secret Sharing
fn gen_polynomial(secret: &U512, degree: u8, prime: &U512) -> Coeffs {
    let mut coefficients: Coeffs = Coeffs(Vec::with_capacity(degree as usize + 1));
    coefficients.0.push(*secret);
    for _ in 0..degree {
        coefficients
            .0
            .push(U512::from_be_slice(&random::<[u8; 64]>()) % *prime);
    }
    coefficients
}
/// Computes any given polynomial
fn compute_poly(coefficients: &Coeffs, x: u8, prime: &U512) -> Result<U512, ReconError> {
    let mut result = U512::ZERO;
    let prime_nz = &uint_to_nz_uint(prime)?;
    let x = U512::from_u8(x);
    for coefficient in coefficients.0.iter().rev() {
        result = result.mul_mod(&x, prime_nz);
        result = result.add_mod(coefficient, prime_nz);
    }
    Ok(result)
}
