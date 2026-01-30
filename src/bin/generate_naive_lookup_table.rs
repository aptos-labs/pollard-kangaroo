//! Binary to generate precomputed naive lookup tables.
//!
//! Usage: cargo run --bin generate_naive_lookup_table --features serde -- <bits>
//!
//! Example: cargo run --bin generate_naive_lookup_table --features serde -- 16

use anyhow::{Context, Result};
use pollard_kangaroo::naive_lookup::NaiveLookup;
use pollard_kangaroo::DlogSolver;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <bits>", args[0]);
        eprintln!("Example: {} 16", args[0]);
        std::process::exit(1);
    }

    let bits: u8 = args[1].parse().context("failed to parse bits argument")?;

    if bits < 1 || bits > 24 {
        anyhow::bail!("bits must be between 1 and 24 (naive lookup uses O(2^bits) storage)");
    }

    let table_size: u64 = 1 << bits;

    println!("Generating naive lookup table for {}-bit secrets...", bits);
    println!("Table will contain {} entries", table_size);
    println!("This will take some time...");

    let start = std::time::Instant::now();
    let naive = NaiveLookup::new_and_compute_table(bits);
    let elapsed = start.elapsed();

    println!("Table generated in {:.2}s", elapsed.as_secs_f64());

    // Serialize and save
    let output_path = format!("src/naive_lookup/rsc/table_{}", bits);
    let output_path = Path::new(&output_path);

    // Create parent directories if they don't exist
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create output directory")?;
    }

    let serialized =
        bincode::serialize(&naive).context("failed to serialize naive lookup table")?;

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
