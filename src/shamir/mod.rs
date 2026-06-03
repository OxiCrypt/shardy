//! This module implements Shamir's Secret Sharing.
mod make_shares;
mod recover_file;
use crypto_bigint::{NonZero, U512};
pub use make_shares::shamir_split;
pub use recover_file::reconstruct_secret_mod;
use zeroize::Zeroize;
#[derive(Debug)]
pub enum ReconError {
    TooFewShares(u8), // Signifies too few shares to compute polynomial
    ModError,         // Signifies error where modulus is zero
    DuplicateShares,  // Signifies error where two identical
}
#[derive(Zeroize)]
pub struct Coeffs(Vec<U512>);
impl Drop for Coeffs {
    fn drop(&mut self) {
        self.zeroize();
    }
}
#[derive(Zeroize)]
pub struct Shares(Vec<(u8, U512)>);
impl Drop for Shares {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Shares {
    pub fn as_slice(&self) -> &[(u8, U512)] {
        self.0.as_slice()
    }
}
// Helper Functions
// This is a helper function because I could not find a way to get const working
fn make_prime() -> U512 {
    // What you will read is the smallest prime above 2^256.
    // I will not be using Mersenne primes because they will be much bigger and slower
    U512::from_be_hex(
        "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000129",
    )
    // This will always produce a valid biguint
}
// Nonzeroers
fn uint_to_nz_uint(n: &U512) -> Result<NonZero<U512>, ReconError> {
    n.to_nz().ok_or(ReconError::ModError)
}
mod tests {
    #[test]
    fn shamir_roundtrip_3_of_5() {
        use super::{reconstruct_secret_mod, shamir_split};
        use crypto_bigint::U512;
        use rand::random;
        use zeroize::Zeroizing;

        for _ in 0..100 {
            let secret = Zeroizing::new(random::<[u8; 32]>());

            let shares = shamir_split(
                std::num::NonZero::new(3).unwrap(),
                std::num::NonZero::new(5).unwrap(),
                &secret,
            )
            .unwrap();
            let mut padded = [0u8; 64];
            padded[32..].copy_from_slice(secret.as_ref());
            let expected = U512::from_be_slice(&padded);

            for a in 0..3 {
                for b in (a + 1)..4 {
                    for c in (b + 1)..5 {
                        let subset = [shares.0[a], shares.0[b], shares.0[c]];

                        let recovered = reconstruct_secret_mod(&subset, 3).unwrap();

                        assert_eq!(recovered, expected, "failed on subset [{a}, {b}, {c}]",);
                    }
                }
            }
        }
    }
}
