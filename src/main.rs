#![warn(clippy::pedantic)]
mod ecdc;
mod keyfile;
mod shamir;
use self::EncOrDec::{Decrypt, Encrypt};
use clap::{Parser, Subcommand};
#[allow(unused_imports)]
#[allow(dead_code)]
use ecdc::{EncError, decrypt_file, encrypt_file};
#[allow(unused_imports)]
use shamir::{reconstruct_secret_mod, shamir_split};
use std::num::NonZero;
use std::path::PathBuf;
use std::{fs::File, io::Write};
use zeroize::Zeroize;
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
        num_shares_out: NonZero<u8>,
        #[arg(short, long)]
        min_shares: NonZero<u8>,
    },
    Decrypt {
        #[arg(short, long)]
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
            let Ok(mut input_file) = File::open(&cli_options.input) else {
                return Err(MainError::InvalidInput("Invalid Path: Input".to_string()));
            };
            let Ok(mut output_file) = File::create(match cli_options.output {
                Some(o) => o,
                None => cli_options.input.with_added_extension("shdy"),
            }) else {
                return Err(MainError::InvalidInput("Invalid Path: Output".to_string()));
            };
            match encrypt_file(&mut input_file, &mut output_file, &keyfile, min_shares) {
                Ok(()) => (),
                Err(e) => {
                    return Err(MainError::InternalError(format!("{e:?}")));
                }
            }
            println!("Encryption Complete! Splitting Shares...");
            let Ok(shares) = shamir_split(min_shares, num_shares_out, &keyfile) else {
                return Err(MainError::InternalError(
                    "What did you do in GDB?".to_string(),
                ));
            };
            for (index, share) in shares.as_slice().iter().enumerate() {
                let mut to_write = [0u8; 65];
                to_write[0] = share.0;
                let slice_of_i = share.1.to_be_bytes();
                to_write[1..65].copy_from_slice(&slice_of_i.as_slice()[..(65 - 1)]);
                let mut target = index.to_string();
                target.insert_str(0, &share_prefix);
                let Ok(mut out) = File::create(target) else {
                    return Err(MainError::InvalidInput(
                        "Something went wrong while creating a share. Most likely: Permissions."
                            .to_string(),
                    ));
                };
                if out.write(&to_write).is_err() {
                    return Err(MainError::InternalError(
                        "Failed to Write share, but share created. Most likely: Write interrupted."
                            .to_string(),
                    ));
                }
                to_write.zeroize();
            }
        }
        Decrypt { share_prefix } => {
            todo!("Decryption Pipeline {share_prefix}");
        }
    }
    Ok(())
}
