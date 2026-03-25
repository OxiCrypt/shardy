use std::ops::ShrAssign;

use crypto_bigint::{I512, NonZero, U512, Uint};
use rand::random;
pub enum ReconError {
    TooFewShares(u8), // Signifies too few shares to compute polynomial
    Contradicting,    // Signifies one or more points contradict
    ModError,         // Signifies error where modulus is zero
}
fn uint_to_nz_int(n: &U512) -> Result<NonZero<I512>, ReconError> {
    n.as_int().to_nz().ok_or(ReconError::ModError)
}
fn uint_to_nz_uint(n: &U512) -> Result<NonZero<U512>, ReconError> {
    n.to_nz().ok_or(ReconError::ModError)
}
pub fn shamir_split(
    threshold: u8,
    shares: NonZero<u8>,
    secret: &U512,
) -> Result<Vec<(u8, U512)>, ReconError> {
    let prime = make_prime();
    let coeffs = gen_polynomial(secret, threshold, &prime);
    let mut result: Vec<(u8, U512)> = Vec::new();
    for i in 1..=shares.get() {
        result.push((i, compute_poly(coeffs.as_slice(), i, &prime)?));
    }
    Ok(result)
}
fn make_prime() -> U512 {
    // What you will read is the smallest prime above 2^256.
    // I will not be using Mersenne primes because they will be much bigger and slower
    Uint::from_be_hex("10000000000000000000000000000000000000000000000000000000000000129")
    // This will always produce a valid biguint
}
fn gen_polynomial(secret: &U512, degree: u8, prime: &U512) -> Vec<U512> {
    let mut coefficients: Vec<U512> = Vec::with_capacity(degree as usize);
    coefficients.push(*secret);
    for _ in 0..degree - 1 {
        coefficients.push(U512::from_be_slice(&random::<[u8; 64]>()) % *prime);
    }
    coefficients
}

fn compute_poly(coefficients: &[U512], x: u8, prime: &U512) -> Result<U512, ReconError> {
    let mut result = U512::ZERO;

    let x = U512::from_u8(x);
    for coefficient in coefficients.iter().rev() {
        result = (result * x).add_mod(coefficient, &uint_to_nz_uint(prime)?);
    }
    Ok(result)
}
fn mod_inverse(prime: &U512, a: &U512) -> Result<U512, ReconError> {
    let mut exp: U512 = *prime - U512::from_u8(2);
    let prime = uint_to_nz_uint(prime)?;
    let mut result = U512::ONE;
    let mut base = a % prime;
    while exp.is_nonzero().to_bool() {
        if exp.is_odd().to_bool() {
            result = result.mul_mod(&base, &prime);
        }
        base = base.mul_mod(&base, &prime);
        exp.shr_assign(1);
    }
    Ok(result)
}
pub fn reconstruct_secret_mod(
    shares: &[(u8, U512)],
    p: &U512,
    req: u8,
) -> Result<I512, ReconError> {
    let n = shares.len();
    if n < req as usize {
        return Err(ReconError::TooFewShares(req));
    }
    let p_signed = uint_to_nz_int(p)?;
    let p_unsigned = uint_to_nz_uint(p)?;
    let mut secret = I512::ZERO;

    for i in 0..n {
        let (xi, yi) = shares[i];
        let xi = Uint::from_u8(xi);
        let mut term = *yi.rem(&p_unsigned).as_int();

        for (j, _) in shares {
            if i != *j as usize {
                let xj = U512::from_u8(*j);
                let numerator = (*U512::ZERO.as_int() - *xj.as_int()).rem(&p_signed);
                let denominator = ((xi - xj).rem(&p_unsigned) + p_unsigned.get()).rem(&p_unsigned);
                term = (term * numerator % p_signed) * mod_inverse(p, &denominator)? % p_signed;
            }
        }

        secret = (secret + term) % p_signed;
    }

    Ok(secret)
}
