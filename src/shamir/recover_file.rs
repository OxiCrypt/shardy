use super::ReconError;
use super::{uint_to_nz_int, uint_to_nz_uint};
use crypto_bigint::{I512, U512, Uint};
use std::ops::ShrAssign;
/// Finds the modular inverse of a given a prime number is the modulus.
/// Uses Fermat's little theorem(Fermat my GOAT)
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
// Reconstructs the secret from points on the polynomial. Uses Lagrange Interpolation
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
