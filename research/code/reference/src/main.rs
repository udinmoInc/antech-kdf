//! CLI for the readable Antech KDF reference implementation.

use antech_kdf_reference::{derive, RefConfig, GRAPH_COMBINED_FRONTIER};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "antech-kdf-reference",
    about = "Review reference Derive (not production)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Derive a digest (hex) from password + salt hex.
    Derive {
        #[arg(long)]
        password: String,
        #[arg(long)]
        salt_hex: String,
        #[arg(long, default_value_t = 1024)]
        memory_kib: usize,
        #[arg(long, default_value_t = 32)]
        block_size: usize,
        #[arg(long, default_value_t = 2)]
        fan_in: u32,
        #[arg(long, default_value_t = 32)]
        output_length: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Derive {
            password,
            salt_hex,
            memory_kib,
            block_size,
            fan_in,
            output_length,
        } => {
            let salt = hex::decode(&salt_hex).expect("salt_hex");
            let cfg = RefConfig {
                memory_kib,
                block_size,
                fan_in,
                graph_tag: GRAPH_COMBINED_FRONTIER,
                output_length,
            };
            let dig = derive(password.as_bytes(), &salt, &cfg);
            println!("{}", hex::encode(dig));
        }
    }
}
