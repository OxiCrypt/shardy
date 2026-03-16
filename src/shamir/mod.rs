use num_bigint::BigInt;
fn shamir_split(threshold: u8) {
    let prime: BigInt = make_prime();
}
fn make_prime() -> BigInt {
    // What you will read is the smallest prime above 2^256. I will not be using Mersenne primes because they will be much bigger and slower
    BigInt::parse_bytes(
        b"115792089237316195423570985008687907853269984665640564039457584007913129640233",
        10,
    )
    .unwrap()
    // This will always produce a valid biguint
}
fn positive_modp(x: BigInt, p: &BigInt) -> BigInt {
    ((x % p) + p) % p
}
fn compute_poly(coefficients: &[BigInt], x: &BigInt, p: &BigInt) -> BigInt {
    let mut result = BigInt::ZERO;
    for coefficient in coefficients.iter().rev() {
        result = positive_modp(result * x + coefficient, p);
    }
    result
}
