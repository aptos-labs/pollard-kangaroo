//! Binary to generate precomputed BL12 tables.
//!
//! Usage: cargo run --bin generate_bl12_table --features "bl12,serde" -- <bits>
//!
//! Example: cargo run --bin generate_bl12_table --features "bl12,serde" -- 32

use anyhow::{Context, Result};
use ristretto255_dlog::bl12::Bl12;
use ristretto255_dlog::DiscreteLogSolver;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <bits>", args[0]);
        eprintln!("Example: {} 32", args[0]);
        std::process::exit(1);
    }

    let bits: u8 = args[1].parse().context("failed to parse bits argument")?;

    if bits < 8 || bits > 64 {
        anyhow::bail!("bits must be between 8 and 64");
    }

    println!("Generating BL12 table for {}-bit secrets...", bits);
    println!("This will take some time (random walks to find distinguished points)...");

    let start = std::time::Instant::now();
    let bl12 = Bl12::new_and_compute_table(bits);
    let elapsed = start.elapsed();

    println!("Table generated in {:.2}s", elapsed.as_secs_f64());
    println!(
        "Parameters: i={}, W={}, N={}, R={}",
        bl12.table.i, bl12.table.W, bl12.table.N, bl12.table.R
    );
    println!(
        "Distinguished points found: {}",
        bl12.table.distinguished_points.len()
    );

    // Serialize and save
    let output_path = format!("src/bl12/rsc/table_{}", bits);
    let output_path = Path::new(&output_path);

    // Create parent directories if they don't exist
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create output directory")?;
    }

    let serialized = bincode::serialize(&bl12).context("failed to serialize BL12 table")?;

    let mut file = File::create(output_path).context("failed to create output file")?;
    file.write_all(&serialized)
        .context("failed to write to output file")?;

    println!(
        "Table saved to {} ({} bytes)",
        output_path.display(),
        serialized.len()
    );

    Ok(())
}
