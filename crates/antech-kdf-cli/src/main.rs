//! Antech KDF command-line utility.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "antech")]
#[command(about = "Antech KDF password hashing utility", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hash a password string
    Hash { password: String },
    /// Verify a password string against an encoded hash
    Verify {
        password: String,
        encoded_hash: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hash { password } => match antech_kdf::hash(&password) {
            Ok(h) => println!("{h}"),
            Err(e) => eprintln!("Error hashing password: {e}"),
        },
        Commands::Verify {
            password,
            encoded_hash,
        } => match antech_kdf::verify(&password, &encoded_hash) {
            Ok(true) => println!("VERIFIED: Password matches hash"),
            Ok(false) => println!("FAILED: Password does not match hash"),
            Err(e) => eprintln!("Error verifying hash: {e}"),
        },
    }
}
