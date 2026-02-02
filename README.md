# Discrete log algorithms

This crate implements several algorithms for computing discrete logarithms on 32-bit values:

- **[BL12]** - Bernstein-Lange 2012 algorithm 
- **BSGS** - Baby-step giant-step algorithm
- **BSGS-k** - A variant of BSGS that uses `double_and_compress_batch` for better performance
- **Naive lookup** - Simple table lookup for small bit sizes (≤16 bits), reuses BSGS tables

 > [!WARNING]
 > The `pollard-kangaroo` crate name is very unfortunate, since it has almost nothing to do with the implemented algorithms: While [BL12] is a kangaroo-like algorithm, it's not actually the Pollard kangaroo algorithm.

## Precomputed tables

Precomputed tables for 32-bit discrete logs are **checked into the repository**:

- `src/bsgs/rsc/table_32` (~2.5 MiB)
- `src/bsgs_k/rsc/table_32` (~2.5 MiB)
- `src/bl12/rsc/table_32` (~256 KiB)

To regenerate the tables (not normally needed):

```bash
./scripts/regenerate_dl_tables.sh
```

## Useful references

 - [Original \[BL12\] paper](docs/cuberoot-20120919.pdf)
 - Distributed Lab's [paper on its implementation](docs/kangaroo_plus_testing.pdf)
