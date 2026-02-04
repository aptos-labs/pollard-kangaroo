#!/bin/bash
#
# Print the sizes of all precomputed tables in human-readable format.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Function to format number with commas
add_commas() {
    printf "%'d" "$1"
}

# Function to humanize byte sizes
humanize_bytes() {
    local bytes=$1
    local with_commas
    with_commas=$(add_commas "$bytes")
    
    if (( bytes >= 1048576 )); then
        printf "%.2f MiB (%s bytes)" "$(echo "scale=2; $bytes / 1048576" | bc)" "$with_commas"
    elif (( bytes >= 1024 )); then
        printf "%.2f KiB (%s bytes)" "$(echo "scale=2; $bytes / 1024" | bc)" "$with_commas"
    else
        printf "%s bytes" "$with_commas"
    fi
}

echo "Precomputed Table Sizes"
echo "======================="
echo

# Define tables: (algorithm name, path)
tables=(
    "[BL12] 32-bit|src/bl12/rsc/table_32"
    "BSGS 32-bit|src/bsgs/rsc/table_32"
    "BSGS-k 32-bit|src/bsgs_k/rsc/table_32"
    "TBSGS-k 32-bit|src/tbsgs_k/rsc/table_32"
)

for entry in "${tables[@]}"; do
    IFS='|' read -r name path <<< "$entry"
    full_path="$REPO_ROOT/$path"
    
    if [[ -f "$full_path" ]]; then
        size=$(stat -f%z "$full_path" 2>/dev/null || stat -c%s "$full_path" 2>/dev/null)
        printf "%-25s %s\n" "$name:" "$(humanize_bytes "$size")"
    else
        printf "%-25s %s\n" "$name:" "(not found)"
    fi
done

echo
total=0
for entry in "${tables[@]}"; do
    IFS='|' read -r name path <<< "$entry"
    full_path="$REPO_ROOT/$path"
    
    if [[ -f "$full_path" ]]; then
        size=$(stat -f%z "$full_path" 2>/dev/null || stat -c%s "$full_path" 2>/dev/null)
        total=$((total + size))
    fi
done
printf "%-25s %s\n" "Total:" "$(humanize_bytes "$total")"
