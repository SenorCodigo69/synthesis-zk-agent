#!/usr/bin/env node
/**
 * Baby JubJub EdDSA key generation for ZK authorization proofs.
 * Generates owner keypair for signing agent delegation policies.
 *
 * Usage:
 *   node keygen.js                    # Generate new random keypair
 *   node keygen.js <private_key_hex>  # Derive public key from existing private key
 *
 * Output: JSON { privateKey, publicKey: [Ax, Ay] }
 */
const { derivePublicKey } = require("@zk-kit/eddsa-poseidon");
const crypto = require("crypto");

const privKeyArg = process.argv[2];
const privateKey = (privKeyArg === "__FROM_ENV__" ? process.env.ZK_SENSITIVE_ARG : privKeyArg) || crypto.randomBytes(32).toString("hex");

const publicKey = derivePublicKey(privateKey);

console.log(JSON.stringify({
    privateKey: privateKey,
    publicKey: [publicKey[0].toString(), publicKey[1].toString()]
}));
