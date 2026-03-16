#!/usr/bin/env node
/**
 * Poseidon hash helper — computes Poseidon hash matching circomlib's implementation.
 *
 * Usage:
 *   node poseidon_hash.js <input1> <input2> [input3] ...
 *
 * Output: hash value as string
 */
const { poseidon2, poseidon3, poseidon4, poseidon5, poseidon6 } = require("poseidon-lite");

// Inputs can come from CLI args or ZK_HASH_INPUTS env var (avoids leaking in ps aux)
let rawInputs = process.argv.slice(2);
if (rawInputs.length === 1 && rawInputs[0] === "--from-env") {
    const envInputs = process.env.ZK_HASH_INPUTS;
    if (!envInputs) {
        console.error("--from-env requires ZK_HASH_INPUTS env var");
        process.exit(1);
    }
    rawInputs = JSON.parse(envInputs);
}
const inputs = rawInputs.map(BigInt);

if (inputs.length === 0) {
    console.error("Usage: node poseidon_hash.js <input1> <input2> ...");
    process.exit(1);
}

const hashFns = {
    2: poseidon2,
    3: poseidon3,
    4: poseidon4,
    5: poseidon5,
    6: poseidon6
};

const fn = hashFns[inputs.length];
if (!fn) {
    console.error(`Unsupported number of inputs: ${inputs.length} (supported: 2-6)`);
    process.exit(1);
}

const result = fn(inputs);
console.log(result.toString());
