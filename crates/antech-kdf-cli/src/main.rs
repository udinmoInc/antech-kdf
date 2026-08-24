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
    /// Run quick research benchmarks or export full baseline, Phase C, D, and E research suites
    Benchmark {
        /// Number of iterations for quick benchmark
        #[arg(short, long, default_value_t = 10)]
        iterations: u32,

        /// Output directory for exporting research suite results (JSON/CSV/Markdown)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Run Phase C Candidate Research Laboratory (Candidates 001..008)
        #[arg(long, default_value_t = false)]
        phase_c: bool,

        /// Run Phase D Candidate 004 Optimization Laboratory
        #[arg(long, default_value_t = false)]
        phase_d: bool,

        /// Run Phase E Cost-Asymmetric Low-Resource Research Laboratory (Candidates E1..E6)
        #[arg(long, default_value_t = false)]
        phase_e: bool,
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
        Commands::Benchmark {
            iterations,
            output,
            phase_c,
            phase_d,
            phase_e,
        } => {
            if let Some(target_dir) = output {
                if phase_e || target_dir.to_string_lossy().contains("phase-e") {
                    println!("Running Phase E Cost-Asymmetric Research Laboratory...");
                    if let Err(e) = antech_kdf_research::run_phase_e_suite(&target_dir) {
                        eprintln!("Error running Phase E research suite: {}", e);
                    }
                } else if phase_d || target_dir.to_string_lossy().contains("phase-d") {
                    println!("Running Phase D Candidate 004 Optimization Laboratory...");
                    if let Err(e) = antech_kdf_research::run_phase_d_suite(&target_dir) {
                        eprintln!("Error running Phase D research suite: {}", e);
                    }
                } else if phase_c || target_dir.to_string_lossy().contains("phase-c") {
                    println!("Running Phase C Candidate Research Laboratory...");
                    if let Err(e) = antech_kdf_research::run_phase_c_suite(&target_dir) {
                        eprintln!("Error running Phase C research suite: {}", e);
                    }
                } else {
                    println!("Running full Antech research laboratory benchmark suite...");
                    if let Err(e) = antech_kdf_research::run_full_research_suite(&target_dir) {
                        eprintln!("Error running research suite: {}", e);
                    }

                    let phase_c_dir = target_dir.join("phase-c");
                    println!("Running Phase C Candidate Research Laboratory...");
                    if let Err(e) = antech_kdf_research::run_phase_c_suite(&phase_c_dir) {
                        eprintln!("Error running Phase C research suite: {}", e);
                    }

                    let phase_d_dir = target_dir.join("phase-d");
                    println!("Running Phase D Candidate 004 Optimization Laboratory...");
                    if let Err(e) = antech_kdf_research::run_phase_d_suite(&phase_d_dir) {
                        eprintln!("Error running Phase D research suite: {}", e);
                    }

                    let phase_e_dir = target_dir.join("phase-e");
                    println!("Running Phase E Cost-Asymmetric Research Laboratory...");
                    if let Err(e) = antech_kdf_research::run_phase_e_suite(&phase_e_dir) {
                        eprintln!("Error running Phase E research suite: {}", e);
                    }
                }
            } else {
                println!("Running Antech KDF benchmark ({} iterations)...", iterations);
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
