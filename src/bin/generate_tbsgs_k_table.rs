//! Binary to generate precomputed TBSGS-k tables.
//!
//! Usage: cargo run --bin generate_tbsgs_k_table --features "tbsgs_k,serde" -- <bits>
//!
//! Example: cargo run --bin generate_tbsgs_k_table --features "tbsgs_k,serde" -- 32

use anyhow::{Context, Result};
use pollard_kangaroo::tbsgs_k::TruncatedBabyStepGiantStepKTable;
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

    if bits < 8 || bits > 32 {
        anyhow::bail!("bits must be between 8 and 32 (u16 values require m <= 65536)");
    }

    // m = ceil(sqrt(2^bits)) = 2^(ceil(bits/2))
    let m: u64 = 1 << ((bits + 1) / 2);

    println!("Generating TBSGS-k table for {}-bit secrets...", bits);
    println!("Table size m = {} (truncated 8-byte keys)", m);
    println!("This will take some time...");

    let start = std::time::Instant::now();
    let table = TruncatedBabyStepGiantStepKTable::generate(bits);
    let elapsed = start.elapsed();

    println!("Table generated in {:.2}s", elapsed.as_secs_f64());

    // Serialize and save
    let output_path = format!("src/tbsgs_k/rsc/table_{}", bits);
    let output_path = Path::new(&output_path);

    // Create parent directories if they don't exist
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create output directory")?;
    }

    let serialized = table
        .to_bytes()
        .context("failed to serialize TBSGS-k table")?;

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
