# Discrete log algorithms

This crate implements several algorithms for computing discrete logarithms on 32-bit values:

- **[BL12]** - Bernstein-Lange 2012 algorithm 
- **BSGS** - Baby-step giant-step algorithm
- **BSGS-k** - A variant of BSGS that uses `double_and_compress_batch` for better performance
- **Naive lookup** - Simple table lookup for small bit sizes (≤24 bits)

 > [!WARNING]
 > The `pollard-kangaroo` crate name is very unfortunate, since it has almost nothing to do with the implemented algorithms: While [BL12] is a kangaroo-like algorithm, it's not actually the Pollard kangaroo algorithm.

## Useful references

 - [Original \[BL12\] paper](docs/cuberoot-20120919.pdf)
 - Distributed Lab's [paper on its implementation](docs/kangaroo_plus_testing.pdf)
