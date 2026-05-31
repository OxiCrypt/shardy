use super::ReconError;
use super::{uint_to_nz_int, uint_to_nz_uint};
use crypto_bigint::{I512, U512};
use std::ops::ShrAssign;

/// Finds the modular inverse of `a` given that `prime` is the modulus.
/// Uses Fermat's little theorem: a^(p-2) mod p = a^(-1) mod p.
fn mod_inverse(prime: &U512, a: &U512) -> Result<U512, ReconError> {
    let mut exp: U512 = *prime - U512::from_u8(2);
    let prime_nz = uint_to_nz_uint(prime)?;
    let mut result = U512::ONE;
    let mut base = a % prime_nz;

    while exp.is_nonzero().to_bool() {
        if exp.is_odd().to_bool() {
            result = result.mul_mod(&base, &prime_nz);
        }
        base = base.mul_mod(&base, &prime_nz);
        exp.shr_assign(1);
    }

    Ok(result)
}

/// Reconstructs the secret from shares on the polynomial using Lagrange interpolation.
///
/// `shares` is a slice of (x, y) pairs where x is the share index (1-based) and
/// y is the share value. `p` is the prime modulus. `req` is the minimum threshold.
pub fn reconstruct_secret_mod(
    shares: &[(u8, U512)],
    p: &U512,
    req: u8,
) -> Result<I512, ReconError> {
    let n = shares.len();

    if n < req as usize {
        return Err(ReconError::TooFewShares(req));
    }

    // Bug fix: check for duplicate x-coordinates up front to avoid
    // a zero denominator (and infinite loop) in mod_inverse.
    for i in 0..n {
        for j in (i + 1)..n {
            if shares[i].0 == shares[j].0 {
                return Err(ReconError::DuplicateShares);
            }
        }
    }

    let p_signed = uint_to_nz_int(p)?;
    let p_unsigned = uint_to_nz_uint(p)?;
    let mut secret = I512::ZERO;

    for i in 0..n {
        let (xi, yi) = shares[i];
        let xi = U512::from_u8(xi);

        // Start the basis term from yi mod p, cast to signed arithmetic.
        let mut term = *yi.rem(&p_unsigned).as_int();

        // Bug fix: iterate by index `j` (not by destructuring the share tuple),
        // so the `i != j` guard compares indices, not x-coordinate values.
        for j in 0..n {
            if i != j {
                let (xj, _) = shares[j];
                let xj = U512::from_u8(xj);

                // numerator = (0 - xj) mod p  →  signed
                let numerator = (*U512::ZERO.as_int() - *xj.as_int()).rem(&p_signed);

                // denominator = (xi - xj) mod p  →  unsigned (always positive after reduction)
                let denominator = ((xi - xj).rem(&p_unsigned) + p_unsigned.get()).rem(&p_unsigned);

                // Bug fix: convert the U512 inverse to I512 before multiplying
                // so we stay in signed arithmetic throughout.
                let inv = *mod_inverse(p, &denominator)?.as_int();

                term = term * numerator % p_signed;
                term = term * inv % p_signed;
            }
        }

        secret = (secret + term) % p_signed;
    }

    // Bug fix: normalise the result into [0, p) because intermediate signed
    // reductions can leave `secret` negative.
    if secret.is_negative().to_bool() {
        secret = (secret + p_signed.get()).rem(&p_signed);
    }

    Ok(secret)
}
