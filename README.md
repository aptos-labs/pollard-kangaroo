# ristretto255-dlog

Discrete log algorithms for Ristretto255 elliptic curves.

This crate implements several algorithms for computing discrete logarithms on 32-bit values:

- **[BL12]** - Bernstein-Lange 2012 algorithm 
- **BSGS** - Baby-step giant-step algorithm
- **BSGS-k** - A variant of BSGS that uses `double_and_compress_batch` for better performance
- **TBSGS-k** - Truncated BSGS-k with 8-byte keys (75% smaller tables)
- **Naive lookup** - Simple table lookup for small bit sizes (≤16 bits), reuses BSGS tables

## Precomputed tables

Precomputed tables for 32-bit discrete logs are **checked into the repository**:

- `src/bsgs/rsc/table_32` (~2.5 MiB)
- `src/bsgs_k/rsc/table_32` (~2.5 MiB)
- `src/tbsgs_k/rsc/table_32` (~512 KiB)
- `src/bl12/rsc/table_32` (~256 KiB)

To regenerate the tables (not normally needed), use the provided scripts:

```bash
./scripts/regenerate_bl12_table.sh
./scripts/regenerate_bsgs_tables.sh
./scripts/regenerate_tbsgs_k_table.sh
```

## Useful references

 - [Original \[BL12\] paper](docs/cuberoot-20120919.pdf)
 - Distributed Lab's [paper on its implementation](docs/kangaroo_plus_testing.pdf)
