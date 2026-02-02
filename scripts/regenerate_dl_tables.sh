#!/bin/bash
# Regenerates all precomputed discrete log tables.
#
# WARNING: This will overwrite existing tables and takes several minutes to complete.
#
# Tables generated:
# - BSGS 32-bit:   src/bsgs/rsc/table_32
# - BSGS-k 32-bit: src/bsgs_k/rsc/table_32
# - BL12 32-bit:   src/bl12/rsc/table_32

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

echo "=============================================="
echo "Regenerating all discrete log precomputed tables"
echo "=============================================="
echo ""
echo "WARNING: This will overwrite existing tables!"
echo ""

# BSGS 32-bit table
echo ">>> Generating BSGS 32-bit table..."
cargo run --release --bin generate_bsgs_table --features "bsgs,serde" -- 32
echo ""

# BSGS-k 32-bit table
echo ">>> Generating BSGS-k 32-bit table..."
cargo run --release --bin generate_bsgs_k_table --features "bsgs_k,serde" -- 32
echo ""

# BL12 32-bit table
echo ">>> Generating BL12 32-bit table..."
cargo run --release --bin generate_bl12_table --features "bl12,serde" -- 32
echo ""

echo "=============================================="
echo "All tables regenerated!"
echo "=============================================="
echo ""
echo "Tables updated:"
echo "  - src/bsgs/rsc/table_32"
echo "  - src/bsgs_k/rsc/table_32"
echo "  - src/bl12/rsc/table_32"
