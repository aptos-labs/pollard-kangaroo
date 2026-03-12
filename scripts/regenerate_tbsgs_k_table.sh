#!/bin/bash
# Regenerate the TBSGS-k 32-bit precomputed table.

set -e

echo "Generating TBSGS-k 32-bit table..."
cargo run --release --bin generate_tbsgs_k_table --features "tbsgs_k,serde" -- 32

echo "Done!"
