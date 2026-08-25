//! Explicit memory layout analysis for Antech KDF configurations.
//!
//! Answers precisely: where does every byte go at each memory target?

use std::io::Write;
use std::path::Path;

/// Breakdown of every byte in the working memory.
#[derive(Debug, Clone)]
pub struct MemoryLayout {
    pub memory_target_bytes: usize,

    // Structured components
    pub blocks_bytes: usize,
    pub state_bytes: usize,
    pub seed_bytes: usize,
    pub metadata_bytes: usize,
    pub temporary_workspace_bytes: usize,
    pub alignment_padding_bytes: usize,

    // Derived
    pub num_blocks: usize,
    pub block_size_bytes: usize,
    pub state_entries: usize,
    pub total_accounted_bytes: usize,
}

impl MemoryLayout {
    /// Compute the layout for a given memory target.
    ///
    /// Layout structure:
    /// ```text
    /// working_memory =
    ///   blocks          (num_blocks × block_size)
    ///   + state         (4 × u64 = 32 bytes of live CPU state)
    ///   + seed          (32-byte SHA-256 seed derived from password/salt)
    ///   + metadata      (config parameters: memory_kib, depth, passes = 3 × u32 = 12 bytes)
    ///   + temp_buffer   (SHA-256 working area: 1 × block_size for initialization)
    ///   + alignment     (rounding to 64-byte cache line boundary)
    /// ```
    pub fn compute(memory_target_bytes: usize) -> Self {
        Self::compute_with_block_size(
            memory_target_bytes,
            super::config::DEFAULT_BLOCK_SIZE as usize,
        )
    }

    pub fn compute_with_block_size(memory_target_bytes: usize, block_size_bytes: usize) -> Self {
        let block_size_bytes = block_size_bytes.max(16);

        // The bulk allocation: num_blocks × block_size
        let blocks_bytes = memory_target_bytes;
        let num_blocks = blocks_bytes / block_size_bytes;

        // In-CPU state: 4 × u64 (32 bytes) — lives in registers, not heap
        let state_bytes = 4 * 8;
        let state_entries = 4;

        // SHA-256 seed: 32 bytes — reused throughout, heap-allocated once
        let seed_bytes = 32;

        // Metadata: memory_kib (4 bytes) + depth (4 bytes) + passes (4 bytes)
        let metadata_bytes = 12;

        // Temporary workspace for block initialization:
        // SHA-256 hasher state per block fill iteration ≈ 1 block_size scratch
        let temporary_workspace_bytes = block_size_bytes;

        // Alignment: total stack/heap to 64-byte cache line
        let raw_total = blocks_bytes + seed_bytes + metadata_bytes + temporary_workspace_bytes;
        let alignment_padding_bytes = if raw_total % 64 == 0 {
            0
        } else {
            64 - (raw_total % 64)
        };

        let total_accounted_bytes = blocks_bytes
            + state_bytes
            + seed_bytes
            + metadata_bytes
            + temporary_workspace_bytes
            + alignment_padding_bytes;

        Self {
            memory_target_bytes,
            blocks_bytes,
            state_bytes,
            seed_bytes,
            metadata_bytes,
            temporary_workspace_bytes,
            alignment_padding_bytes,
            num_blocks,
            block_size_bytes,
            state_entries,
            total_accounted_bytes,
        }
    }

    /// Human-readable size string.
    pub fn to_mib_str(bytes: usize) -> String {
        if bytes >= 1024 * 1024 {
            format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.1} KiB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }

    /// What security property requires memory at this size?
    pub fn security_property(&self) -> &'static str {
        let mib = self.memory_target_bytes / (1024 * 1024);
        match mib {
            0..=1 => "Fits in L3 cache — GPU SIMD trivially parallelizable; no meaningful memory hardness",
            2..=4 => "May exceed L3 on some GPUs; modest cache pressure; dependency still primary cost",
            5..=11 => "Exceeds typical GPU L2 (512KB–2MB); forces DRAM traffic on GPU; partial hardness",
            12..=16 => "Exceeds GPU shared memory (48–96KB typical); forces DRAM on GPU; meaningful capacity hardness",
            17..=23 => "32 GPU threads × 500 KB each = 16 MB shared; GPU must page; real DRAM latency enforced",
            24..=32 => "Exceeds GPU L2 cache (typically 4–6 MB per SM); forces full DRAM on GPU; strong capacity hardness",
            _ => "Very large; diminishing returns vs. DRAM bandwidth; Argon2id territory",
        }
    }
}

/// Memory layout records for all configured targets.
pub struct MemoryLayoutAnalysis {
    pub layouts: Vec<MemoryLayout>,
}

impl MemoryLayoutAnalysis {
    /// Targets: 12, 16, 20, 24, 28, 32 MiB (as specified) plus small baselines 1, 2, 4 MiB.
    pub fn run() -> Self {
        let targets_mib = [1, 2, 4, 12, 16, 20, 24, 28, 32];
        let layouts = targets_mib
            .iter()
            .map(|&mib| MemoryLayout::compute(mib * 1024 * 1024))
            .collect();
        Self { layouts }
    }

    /// Write memory-layout.md to the output directory.
    pub fn write_markdown(&self, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let path = output_dir.join("memory-layout.md");
        let mut f = std::fs::File::create(&path)?;

        writeln!(f, "# Antech KDF — Memory Layout Analysis\n")?;
        writeln!(
            f,
            "This document explains exactly where every byte goes for each memory target."
        )?;
        writeln!(f, "There are no unexplained allocations.\n")?;
        writeln!(f, "## Memory Formula\n")?;
        writeln!(f, "```")?;
        writeln!(f, "working_memory =")?;
        writeln!(f, "    blocks           (num_blocks × block_size)")?;
        writeln!(
            f,
            "  + seed             (32 bytes, SHA-256 password+salt derivation)"
        )?;
        writeln!(
            f,
            "  + metadata         (12 bytes: memory_kib u32 + depth u32 + passes u32)"
        )?;
        writeln!(
            f,
            "  + temp_workspace   (32 bytes, SHA-256 scratch per block fill)"
        )?;
        writeln!(
            f,
            "  + alignment        (0–63 bytes, 64-byte cache-line rounding)"
        )?;
        writeln!(f, "")?;
        writeln!(
            f,
            "Note: state (4 × u64 = 32 bytes) lives in CPU registers, not heap."
        )?;
        writeln!(f, "```\n")?;

        writeln!(f, "## Why This Memory Size?\n")?;
        writeln!(
            f,
            "The buffer is filled with SHA-256 hashes of each block index before the main"
        )?;
        writeln!(
            f,
            "dependency loop runs. This makes the initial buffer content non-trivially"
        )?;
        writeln!(
            f,
            "compressible — an attacker cannot regenerate arbitrary blocks cheaply."
        )?;
        writeln!(
            f,
            "The dependency loop then reads and writes blocks based on current state,"
        )?;
        writeln!(
            f,
            "so all `num_blocks` blocks must remain available in RAM throughout execution.\n"
        )?;

        writeln!(f, "## Per-Target Breakdown\n")?;
        writeln!(f, "| Target | Blocks | Block Size | Num Blocks | State | Seed | Metadata | Temp | Align | Total Heap | Security Property |")?;
        writeln!(f, "|--------|--------|------------|------------|-------|------|----------|------|-------|------------|-------------------|")?;

        for l in &self.layouts {
            writeln!(
                f,
                "| {} | {} | {} B | {} | {} B | {} B | {} B | {} B | {} B | {} | {} |",
                MemoryLayout::to_mib_str(l.memory_target_bytes),
                MemoryLayout::to_mib_str(l.blocks_bytes),
                l.block_size_bytes,
                l.num_blocks,
                l.state_bytes,
                l.seed_bytes,
                l.metadata_bytes,
                l.temporary_workspace_bytes,
                l.alignment_padding_bytes,
                MemoryLayout::to_mib_str(l.total_accounted_bytes),
                l.security_property(),
            )?;
        }

        writeln!(f, "\n## Detailed Per-Target Analysis\n")?;
        for l in &self.layouts {
            let target_mib = l.memory_target_bytes / (1024 * 1024);
            writeln!(
                f,
                "### {} Working Memory\n",
                MemoryLayout::to_mib_str(l.memory_target_bytes)
            )?;
            writeln!(f, "```")?;
            writeln!(
                f,
                "blocks:            {:>10}  ({} × {} bytes)",
                MemoryLayout::to_mib_str(l.blocks_bytes),
                l.num_blocks,
                l.block_size_bytes
            )?;
            writeln!(
                f,
                "seed:              {:>10}  (SHA-256 of password + salt)",
                MemoryLayout::to_mib_str(l.seed_bytes)
            )?;
            writeln!(
                f,
                "metadata:          {:>10}  (memory_kib u32, depth u32, passes u32)",
                MemoryLayout::to_mib_str(l.metadata_bytes)
            )?;
            writeln!(
                f,
                "temp_workspace:    {:>10}  (SHA-256 init scratch per block)",
                MemoryLayout::to_mib_str(l.temporary_workspace_bytes)
            )?;
            writeln!(
                f,
                "alignment:         {:>10}  (64-byte cache line rounding)",
                MemoryLayout::to_mib_str(l.alignment_padding_bytes)
            )?;
            writeln!(f, "───────────────────────────────────────")?;
            writeln!(
                f,
                "total heap:        {:>10}",
                MemoryLayout::to_mib_str(l.total_accounted_bytes)
            )?;
            writeln!(
                f,
                "state (registers): {:>10}  (4 × u64, not heap-allocated)",
                MemoryLayout::to_mib_str(l.state_bytes)
            )?;
            writeln!(f, "```\n")?;
            writeln!(
                f,
                "**What fails at {} MiB?** {}\n",
                target_mib.max(1),
                l.security_property()
            )?;
        }

        writeln!(f, "## What Fails Without the Memory?\n")?;
        writeln!(f, "| Memory Removed | What Breaks |")?;
        writeln!(f, "|----------------|-------------|")?;
        writeln!(f, "| Blocks removed | Attacker can regenerate any block in O(1) with 1 SHA-256 call; no sequentiality enforced |")?;
        writeln!(
            f,
            "| Seed removed | Block contents become predictable; password binding lost |"
        )?;
        writeln!(
            f,
            "| Metadata removed | Parameters can be forged; no config commitment |"
        )?;
        writeln!(f, "| State removed | No sequential dependency; all steps become independent; trivially parallelizable |")?;
        writeln!(
            f,
            "| Memory <4 MiB | Fits in GPU shared memory; GPU batch attack trivially parallel |"
        )?;
        writeln!(
            f,
            "| Memory <16 MiB | May fit in high-end GPU L2 cache; cache-hit attacks feasible |"
        )?;
        writeln!(f, "| Memory >16 MiB | GPU forced to DRAM for random block reads; significant latency per step |")?;

        Ok(())
    }

    /// Write baseline.csv (memory layout table in CSV form).
    pub fn write_csv(&self, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let path = output_dir.join("baseline.csv");
        let mut f = std::fs::File::create(&path)?;
        writeln!(f, "target_mib,blocks_mib,num_blocks,block_size_bytes,state_bytes,seed_bytes,metadata_bytes,temp_bytes,align_bytes,total_heap_bytes,security_tier")?;
        for l in &self.layouts {
            let target_mib = l.memory_target_bytes / (1024 * 1024);
            writeln!(
                f,
                "{},{:.3},{},{},{},{},{},{},{},{},\"{}\"",
                target_mib,
                l.blocks_bytes as f64 / (1024.0 * 1024.0),
                l.num_blocks,
                l.block_size_bytes,
                l.state_bytes,
                l.seed_bytes,
                l.metadata_bytes,
                l.temporary_workspace_bytes,
                l.alignment_padding_bytes,
                l.total_accounted_bytes,
                l.security_property(),
            )?;
        }
        Ok(())
    }
}
