//! Antech KDF Command Line Utility & Research CLI.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "antech")]
#[command(about = "Antech KDF research command-line tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hash a password string
    Hash {
        /// Password input string
        password: String,
    },
    /// Verify a password string against an encoded hash
    Verify {
        /// Password input string
        password: String,
        /// Encoded stored hash
        encoded_hash: String,
    },
    /// Run quick research benchmarks or export full benchmark suite
    Benchmark {
        /// Number of iterations for quick benchmark
        #[arg(short, long, default_value_t = 10)]
        iterations: u32,

        /// Output directory for exporting research suite results (CSV/Markdown)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hash { password } => match antech_kdf::hash(&password) {
            Ok(h) => println!("{}", h),
            Err(e) => eprintln!("Error hashing password: {}", e),
        },
        Commands::Verify {
            password,
            encoded_hash,
        } => match antech_kdf::verify(&password, &encoded_hash) {
            Ok(true) => println!("VERIFIED: Password matches hash"),
            Ok(false) => println!("FAILED: Password does not match hash"),
            Err(e) => eprintln!("Error verifying hash: {}", e),
        },
        Commands::Benchmark { iterations, output } => {
            if let Some(target_dir) = output {
                println!("Running Antech KDF research benchmark suite...");
                if let Err(e) = antech_kdf_research::run_research_suite(&target_dir) {
                    eprintln!("Error running research suite: {}", e);
                }
            } else {
                println!(
                    "Running Antech KDF benchmark ({} iterations)...",
                    iterations
                );
                let start = Instant::now();
                for i in 0..iterations {
                    let pass = format!("pass_{}", i);
                    let _h = antech_kdf::hash(&pass).expect("Benchmark hash failed");
                }
                let elapsed = start.elapsed();
                let per_op = elapsed / iterations;
                println!("Total time: {:?}", elapsed);
                println!("Average per hash: {:?}", per_op);
            }
        }
    }
}
