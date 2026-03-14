pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// AuthorizationProof: Proves agent is authorized by owner via EdDSA signature
// without revealing the spending limits or owner's full identity.
//
// Flow:
//   1. Owner signs delegation message = Poseidon(agentId, spendLimit, validUntil, nonce)
//   2. Circuit verifies the signature
//   3. Circuit checks policy commitment matches
//   4. Public: only agentId and policyCommitment are revealed
template AuthorizationProof() {
    // Private inputs — known only to the agent
    signal input ownerPubKeyAx;     // Owner's Baby JubJub public key X
    signal input ownerPubKeyAy;     // Owner's Baby JubJub public key Y
    signal input signatureS;        // EdDSA signature S component
    signal input signatureR8x;      // EdDSA signature R8 point X
    signal input signatureR8y;      // EdDSA signature R8 point Y
    signal input spendLimit;        // Max spend amount (hidden)
    signal input validUntil;        // Expiry timestamp (hidden)
    signal input nonce;             // Anti-replay nonce (hidden)
    signal input salt;              // Commitment salt (hidden)

    // Public inputs
    signal input agentId;           // Agent identifier (public)
    signal input policyCommitment;  // Hash of policy params (public, stored on-chain)

    // Step 1: Compute the delegation message hash
    // message = Poseidon(agentId, spendLimit, validUntil, nonce)
    component msgHash = Poseidon(4);
    msgHash.inputs[0] <== agentId;
    msgHash.inputs[1] <== spendLimit;
    msgHash.inputs[2] <== validUntil;
    msgHash.inputs[3] <== nonce;

    // Step 2: Verify owner's EdDSA signature on the message
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== ownerPubKeyAx;
    sigVerifier.Ay <== ownerPubKeyAy;
    sigVerifier.S <== signatureS;
    sigVerifier.R8x <== signatureR8x;
    sigVerifier.R8y <== signatureR8y;
    sigVerifier.M <== msgHash.out;

    // Step 3: Verify policy commitment matches
    // commitment = Poseidon(ownerPubKeyAx, spendLimit, validUntil, nonce, salt)
    component commitHash = Poseidon(5);
    commitHash.inputs[0] <== ownerPubKeyAx;
    commitHash.inputs[1] <== spendLimit;
    commitHash.inputs[2] <== validUntil;
    commitHash.inputs[3] <== nonce;
    commitHash.inputs[4] <== salt;

    // Constrain: computed commitment must equal the public commitment
    commitHash.out === policyCommitment;
}

component main {public [agentId, policyCommitment]} = AuthorizationProof();
