#![warn(clippy::pedantic)]
#[allow(dead_code)]
mod ecdc;
#[allow(dead_code)]
mod keyfile;
#[allow(dead_code)]
mod shamir;
#[allow(unused_imports)]
use shamir::{reconstruct_secret_mod, shamir_split};
fn main() {
    println!("Hello, world!");
}
