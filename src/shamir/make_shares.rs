use super::ReconError;
use super::make_prime;
use super::uint_to_nz_uint;
use super::{Coeffs, Shares};
use crypto_bigint::U512;
use rand::random;
use zeroize::Zeroizing;
/// Public function to expose splitting functionality
pub fn shamir_split(
    threshold: std::num::NonZero<u8>,
    shares: std::num::NonZero<u8>,
    secret: &Zeroizing<[u8; 32]>,
) -> Result<Shares, ReconError> {
    let mut secret_temp = Zeroizing::new([0u8; 64]);
    secret_temp.as_mut()[32..].copy_from_slice(secret.as_ref());
    let secret = U512::from_be_slice(secret_temp.as_ref());
    let prime = make_prime();
    let coeffs = gen_polynomial(&secret, threshold.get() - 1, &prime);
    let mut result: Shares = Shares(Vec::with_capacity(shares.get() as usize));
    for i in 1..=shares.get() {
        result.0.push((i, compute_poly(&coeffs, i, &prime)?));
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
            // I SEE YOU CRYPTO NERDS ABOUT TO WRITE AN ESSAY ABOUT MODULO BIAS
            // IT'S TINY
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
