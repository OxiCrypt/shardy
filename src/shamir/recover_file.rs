use super::ReconError;
use super::{make_prime, uint_to_nz_uint};
use crypto_bigint::U512;
use std::ops::ShrAssign;
use zeroize::Zeroizing;

/// Finds the modular inverse of `a` given that `prime` is the modulus.
/// Uses Fermat's little theorem: a^(p-2) mod p = a^(-1) mod p.
fn mod_inverse(prime: &U512, a: &U512) -> Result<Zeroizing<U512>, ReconError> {
    let mut exp: U512 = *prime - U512::from_u8(2);
    let prime_nz = uint_to_nz_uint(prime)?;
    let mut result = Zeroizing::new(U512::ONE);
    let mut base = a % prime_nz;

    while exp.is_nonzero().to_bool() {
        if exp.is_odd().to_bool() {
            *result = result.mul_mod(&base, &prime_nz);
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
pub fn reconstruct_secret_mod(shares: &[(u8, U512)], req: u8) -> Result<U512, ReconError> {
    if shares.len() < req as usize {
        return Err(ReconError::TooFewShares(req));
    }

    let shares = &shares[..req as usize];
    let n = shares.len();

    for i in 0..n {
        for j in (i + 1)..n {
            if shares[i].0 == shares[j].0 {
                return Err(ReconError::DuplicateShares);
            }
        }
    }

    let p = make_prime();
    let p_nz = uint_to_nz_uint(&p)?;

    let mut secret = U512::ZERO;

    for i in 0..n {
        let xi = shares[i].0;
        let yi = Zeroizing::new(shares[i].1);
        let xi = U512::from_u8(xi);

        let mut term = *yi % p;

        for (j, share) in shares.iter().enumerate() {
            if i != j {
                let (xj, _) = *share;
                let xj = U512::from_u8(xj);

                // numerator = (0 - xj) mod p
                let numerator = p - xj;

                // denominator = (xi - xj) mod p (safe wrap)
                let denominator = if xi >= xj { xi - xj } else { p - (xj - xi) };

                let inv = mod_inverse(&p, &denominator)?;

                term = term.mul_mod(&numerator, &p_nz);
                term = term.mul_mod(&inv, &p_nz);
            }
        }

        secret = secret.add_mod(&term, &p_nz);
    }

    Ok(secret)
}
