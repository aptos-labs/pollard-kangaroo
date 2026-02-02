#!/bin/bash
#
# Tests that BL12 can solve all 16-bit discrete logs using the precomputed 32-bit table.
#

set -e

cd "$(dirname "${BASH_SOURCE[0]}")/.."

time cargo test --release bl12_solves_all_16bits -- --ignored --nocapture
