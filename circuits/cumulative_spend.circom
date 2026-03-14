pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// CumulativeSpendProof: Proves cumulative spending is within period limit
// without revealing the limit, individual amounts, or running total.
//
// Chained proof design:
//   - Each spend creates a new commitment to the updated total
//   - Next proof must reference the previous commitment (chain of trust)
//   - Period resets create a fresh commitment with total=0
template CumulativeSpendProof(n) {
    // Private inputs
    signal input currentTotal;      // Running total before this spend
    signal input newAmount;         // Amount being spent now
    signal input periodLimit;       // Max allowed for the period
    signal input previousSalt;      // Salt used in previous commitment
    signal input newSalt;           // Fresh salt for new commitment

    // Public inputs
    signal input previousCommitment; // Commitment to previous state (on-chain)

    // Public outputs
    signal output newCommitment;    // Commitment to updated state
    signal output withinLimit;      // 1 if within limit, 0 otherwise

    // Range-constrain all values to n bits
    component totalBits = Num2Bits(n);
    totalBits.in <== currentTotal;

    component amountBits = Num2Bits(n);
    amountBits.in <== newAmount;

    component limitBits = Num2Bits(n);
    limitBits.in <== periodLimit;

    // Reject zero-amount spends (prevents commitment chain gaming)
    component amountGt0 = GreaterThan(n);
    amountGt0.in[0] <== newAmount;
    amountGt0.in[1] <== 0;
    amountGt0.out === 1;

    // Step 1: Verify previous commitment (chain integrity)
    // previousCommitment == Poseidon(currentTotal, periodLimit, previousSalt)
    component prevHash = Poseidon(3);
    prevHash.inputs[0] <== currentTotal;
    prevHash.inputs[1] <== periodLimit;
    prevHash.inputs[2] <== previousSalt;
    prevHash.out === previousCommitment;

    // Step 2: Compute new total
    signal newTotal;
    newTotal <== currentTotal + newAmount;

    // Range-constrain new total (overflow protection)
    component newTotalBits = Num2Bits(n);
    newTotalBits.in <== newTotal;

    // Step 3: Check newTotal <= periodLimit
    component leq = LessEqThan(n);
    leq.in[0] <== newTotal;
    leq.in[1] <== periodLimit;
    withinLimit <== leq.out;

    // Step 4: Commit to new state
    // newCommitment = Poseidon(newTotal, periodLimit, newSalt)
    component newHash = Poseidon(3);
    newHash.inputs[0] <== newTotal;
    newHash.inputs[1] <== periodLimit;
    newHash.inputs[2] <== newSalt;
    newCommitment <== newHash.out;
}

component main {public [previousCommitment]} = CumulativeSpendProof(64);
