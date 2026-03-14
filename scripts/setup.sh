#!/bin/bash
# Trusted setup ceremony for all circuits (Groth16)
# Downloads powers of tau if not present, then runs per-circuit setup.
# Usage: ./scripts/setup.sh

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
PTAU_FILE="$BUILD_DIR/pot14_final.ptau"

# Download powers of tau (2^14 = 16384 constraints, enough for our circuits)
if [ ! -f "$PTAU_FILE" ]; then
    echo "=== Downloading powers of tau (2^14) ==="
    curl -L -o "$PTAU_FILE" \
        "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau"
    echo "Downloaded: $PTAU_FILE"
fi

CIRCUITS=("budget_range" "authorization" "cumulative_spend")

for circuit in "${CIRCUITS[@]}"; do
    echo ""
    echo "=== Setting up $circuit ==="

    R1CS="$BUILD_DIR/${circuit}.r1cs"
    if [ ! -f "$R1CS" ]; then
        echo "ERROR: $R1CS not found. Run compile.sh first."
        exit 1
    fi

    # Groth16 setup
    echo "  Groth16 setup..."
    snarkjs groth16 setup "$R1CS" "$PTAU_FILE" "$BUILD_DIR/${circuit}_0000.zkey"

    # Contribute to ceremony (deterministic for reproducibility in hackathon)
    echo "  Contributing to ceremony..."
    snarkjs zkey contribute \
        "$BUILD_DIR/${circuit}_0000.zkey" \
        "$BUILD_DIR/${circuit}_final.zkey" \
        --name="synthesis-hackathon" \
        -e="synthesis-zk-agent-hackathon-entropy-$(date +%s)"

    # Export verification key
    echo "  Exporting verification key..."
    snarkjs zkey export verificationkey \
        "$BUILD_DIR/${circuit}_final.zkey" \
        "$BUILD_DIR/${circuit}_verification_key.json"

    # Export Solidity verifier
    echo "  Exporting Solidity verifier..."
    snarkjs zkey export solidityverifier \
        "$BUILD_DIR/${circuit}_final.zkey" \
        "$BUILD_DIR/${circuit}_verifier.sol"

    # Clean up intermediate zkey
    rm -f "$BUILD_DIR/${circuit}_0000.zkey"

    echo "  Done: $circuit"
done

echo ""
echo "=== Setup complete ==="
echo "Verification keys: $BUILD_DIR/*_verification_key.json"
echo "Solidity verifiers: $BUILD_DIR/*_verifier.sol"
echo "Final zkeys: $BUILD_DIR/*_final.zkey"
