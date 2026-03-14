#!/usr/bin/env node
/**
 * EdDSA-Poseidon signing for ZK authorization proofs.
 * Signs a message (field element) with a Baby JubJub private key.
 *
 * Usage:
 *   node sign.js <private_key_hex> <message>
 *
 * Output: JSON { signature: { S, R8: [R8x, R8y] }, publicKey: [Ax, Ay] }
 */
const { derivePublicKey, signMessage } = require("@zk-kit/eddsa-poseidon");

const privateKey = process.argv[2];
const message = BigInt(process.argv[3]);

if (!privateKey || process.argv[3] === undefined) {
    console.error("Usage: node sign.js <private_key_hex> <message>");
    process.exit(1);
}

const publicKey = derivePublicKey(privateKey);
const signature = signMessage(privateKey, message);

console.log(JSON.stringify({
    signature: {
        S: signature.S.toString(),
        R8: [signature.R8[0].toString(), signature.R8[1].toString()]
    },
    publicKey: [publicKey[0].toString(), publicKey[1].toString()]
}));
