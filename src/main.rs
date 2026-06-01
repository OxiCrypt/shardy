#![warn(clippy::pedantic)]
mod ecdc;
mod io;
mod keyfile;
mod shamir;
use self::EncOrDec::{Decrypt, Encrypt};
use clap::{Parser, Subcommand};
use ecdc::{decrypt_file, encrypt_file};
use io::{get_shares, write_shares};
use shamir::{ReconError, reconstruct_secret_mod, shamir_split};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZero;
use std::path::PathBuf;
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(name = "shardy")]
#[command(about = "Encrypts using random key, then splits into shares.")]
#[command(version)]
struct Shardy {
    #[arg(short, long, help = "File to be en/decrypted")]
    input: PathBuf,
    #[arg(short, long, help = "En/decrypted file")]
    output: Option<PathBuf>,
    #[command(subcommand)]
    command: EncOrDec,
}
#[derive(Subcommand)]
enum EncOrDec {
    #[command(about = "Encrypt and split key into shares")]
    Encrypt {
        #[arg(short, long, help = "Prefix of generated shares' names")]
        share_prefix: String,
        #[arg(short, long, help = "Number of shares to export")]
        num_shares_out: NonZero<u8>,
        #[arg(short, long, help = "Number of shares required to decrypt.")]
        min_shares: NonZero<u8>,
    },
    #[command(about = "Recover key from shares and decrypt")]
    Decrypt {
        #[arg(short, long, help = "Prefix of share filenames.")]
        share_prefix: String,
    },
}
impl EncOrDec {}
/// Represents error cases in main
enum MainError {
    /// Represents a error in the program
    InternalError(String),
    /// Represents stupid input that isn't usable for this program
    InvalidInput(String),
}
impl std::fmt::Debug for MainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainError::InvalidInput(msg) | MainError::InternalError(msg) => write!(f, "{msg}"),
        }
    }
}
impl From<shamir::ReconError> for MainError {
    fn from(_: shamir::ReconError) -> Self {
        Self::InternalError("Error Reconstructing Key.".to_string())
    }
}
fn main() -> Result<(), MainError> {
    let cli_options = Shardy::parse();
    match cli_options.command {
        Encrypt {
            share_prefix,
            num_shares_out,
            min_shares,
        } => {
            if num_shares_out < min_shares {
                return Err(MainError::InvalidInput(
                "You must have more or the same amount of shares to export as the minimum share count."
                    .to_string(),
            ));
            }
            let keyfile = keyfile::gen_keyfile();
            let mut input_file = File::open(&cli_options.input)
                .map_err(|_| MainError::InvalidInput("Invalid Path: Input".to_string()))?;
            let mut output_file = File::create(
                cli_options
                    .output
                    .map_or(cli_options.input.with_added_extension("shdy"), |o| o),
            )
            .map_err(|_| MainError::InvalidInput("Invalid Path: Output".to_string()))?;
            encrypt_file(&mut input_file, &mut output_file, &keyfile, min_shares)
                .map_err(|e| MainError::InternalError(format!("{e:?}")))?;
            println!("Encryption Complete! Splitting Shares...");
            let shares = shamir_split(min_shares, num_shares_out, &keyfile)
                .map_err(|_| MainError::InternalError("What did you do in GDB?".to_string()))?;
            write_shares(&shares, &share_prefix)?;
        }
        Decrypt { share_prefix } => {
            let shares = get_shares(&share_prefix)?;
            let mut ciphertext = File::open(&cli_options.input).map_err(|_| {
                MainError::InternalError("Failed to open provided shdy file".to_string())
            })?;
            ciphertext.seek(SeekFrom::Start(4)).map_err(|_| {
                MainError::InternalError("Failed to seek to threshold byte".to_string())
            })?;
            let mut threshold = [0u8; 1];
            if ciphertext.read_exact(&mut threshold).is_err() {
                return Err(MainError::InternalError(
                    "Failed to read threshold byte".to_string(),
                ));
            }
            let key: Zeroizing<[u8; 32]> = Zeroizing::new(
                match reconstruct_secret_mod(shares.as_slice(), threshold[0]) {
                    Ok(o) => o,
                    Err(e) => match e {
                        ReconError::DuplicateShares => {
                            return Err(MainError::InvalidInput("Duplicate Shares".to_string()));
                        }
                        ReconError::ModError => {
                            return Err(MainError::InternalError(
                                "What did you do in GDB?".to_string(),
                            ));
                        }
                        ReconError::TooFewShares(r) => {
                            return Err(MainError::InvalidInput(format!(
                                "Too few shares. Need: {r}"
                            )));
                        }
                    },
                }
                .to_be_bytes()
                .as_slice()[32..] // Last 32 bytes contain key
                    .try_into()
                    .expect("32.. is always 32 long(the slice is 64 bytes long, 64-32=32"),
            );
            let Ok(mut output) = File::create(match cli_options.output {
                Some(o) => o,
                None => cli_options.input.with_extension(""),
            }) else {
                return Err(MainError::InternalError(
                    "Failed to create output file.".to_string(),
                ));
            };
            if let Err(e) = decrypt_file(&mut ciphertext, &mut output, &key) {
                return Err(MainError::InternalError(format!("{e:?}")));
            }
        }
    }
    Ok(())
}
