#!/bin/bash
# Compile all circom circuits to WASM + R1CS
# Usage: ./scripts/compile.sh

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUITS_DIR="$PROJECT_DIR/circuits"
BUILD_DIR="$PROJECT_DIR/build"

mkdir -p "$BUILD_DIR"

CIRCUITS=("budget_range" "authorization" "cumulative_spend")

for circuit in "${CIRCUITS[@]}"; do
    echo "=== Compiling $circuit ==="
    circom "$CIRCUITS_DIR/${circuit}.circom" \
        --r1cs \
        --wasm \
        --sym \
        -o "$BUILD_DIR" \
        -l "$PROJECT_DIR/node_modules"

    echo "  R1CS: $BUILD_DIR/${circuit}.r1cs"
    echo "  WASM: $BUILD_DIR/${circuit}_js/${circuit}.wasm"
    echo "  SYM:  $BUILD_DIR/${circuit}.sym"
    echo ""
done

echo "All circuits compiled successfully."
