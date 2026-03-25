mod make_shares;
mod recover_file;
use crypto_bigint::{I512, NonZero, U512, Uint};
pub use make_shares::shamir_split;
pub use recover_file::reconstruct_secret_mod;
pub enum ReconError {
    TooFewShares(u8), // Signifies too few shares to compute polynomial
    Contradicting,    // Signifies one or more points contradict
    ModError,         // Signifies error where modulus is zero
}
// Helper Functions
// This is a helper function because I could not find a way to get const working
fn make_prime() -> U512 {
    // What you will read is the smallest prime above 2^256.
    // I will not be using Mersenne primes because they will be much bigger and slower
    Uint::from_be_hex("10000000000000000000000000000000000000000000000000000000000000129")
    // This will always produce a valid biguint
}
// Nonzeroers
fn uint_to_nz_int(n: &U512) -> Result<NonZero<I512>, ReconError> {
    n.as_int().to_nz().ok_or(ReconError::ModError)
}
fn uint_to_nz_uint(n: &U512) -> Result<NonZero<U512>, ReconError> {
    n.to_nz().ok_or(ReconError::ModError)
}
