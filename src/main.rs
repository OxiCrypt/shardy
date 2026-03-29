#![warn(clippy::pedantic)]
#[allow(dead_code)]
mod ecdc;
#[allow(dead_code)]
mod keyfile;
#[allow(dead_code)]
mod shamir;
use self::EncOrDec::{Decrypt, Encrypt};
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use ecdc::{decrypt_file, encrypt_file};
#[allow(unused_imports)]
use shamir::{reconstruct_secret_mod, shamir_split};
use std::path::PathBuf;
#[derive(Parser)]
struct Shardy {
    #[arg(short, long)]
    input: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[command(subcommand)]
    command: EncOrDec,
}
#[derive(Subcommand)]
enum EncOrDec {
    Encrypt {
        #[arg(short, long)]
        share_prefix: String,
        #[arg(short, long)]
        num_shares_out: u8,
        #[arg(short, long)]
        min_shares: u8,
    },
    Decrypt {
        #[arg(short, long)]
        share_prefix: String,
    },
}
impl EncOrDec {
    fn is_encrypt(&self) -> bool {
        matches!(*self, Encrypt { .. })
    }
    fn is_decrypt(&self) -> bool {
        !self.is_encrypt()
    }
}
/// Represents error cases in main
enum MainError {
    /// Represents obviously false things that will never occur
    Contradiction,
    /// Represents stupid input that isn't usable for this program
    InvalidInput(String),
}
impl std::fmt::Debug for MainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainError::Contradiction => write!(f, "This Error should not exist."),
            MainError::InvalidInput(msg) => write!(f, "{msg}"),
        }
    }
}
fn main() -> Result<(), MainError> {
    let cli_options = Shardy::parse();
    if cli_options.command.is_encrypt() {
        let Encrypt {
            share_prefix,
            num_shares_out,
            min_shares,
        } = cli_options.command
        else {
            return Err(MainError::Contradiction);
        };
        if num_shares_out == 0 || min_shares == 0 {
            return Err(MainError::InvalidInput(
                "Neither the amount of shares to export nor the amount of shares required can be 0"
                    .to_string(),
            ));
        } else if num_shares_out < min_shares {
            return Err(MainError::InvalidInput(
                "You must have more or the same amount of shares to export as the minimum share count."
                    .to_string(),
            ));
        }
        todo!("Encryption Pipeline");
    } else if cli_options.command.is_decrypt() {
        let Decrypt { share_prefix } = cli_options.command else {
            return Err(MainError::Contradiction);
        };
        todo!("Decryption Pipeline");
    }
    Ok(())
}
