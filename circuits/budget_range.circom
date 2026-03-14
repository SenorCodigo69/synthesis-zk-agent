pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// BudgetRangeProof: Proves amount <= maxBudget without revealing either value.
// Public outputs: commitmentHash (binds to the policy), valid (1 if within budget)
template BudgetRangeProof(n) {
    // Private inputs
    signal input amount;
    signal input maxBudget;
    signal input salt;

    // Public outputs
    signal output commitmentHash;
    signal output valid;

    // Range-constrain inputs to n bits (prevent overflow attacks)
    component amountBits = Num2Bits(n);
    amountBits.in <== amount;

    component budgetBits = Num2Bits(n);
    budgetBits.in <== maxBudget;

    // Check amount <= maxBudget
    component leq = LessEqThan(n);
    leq.in[0] <== amount;
    leq.in[1] <== maxBudget;
    valid <== leq.out;

    // Commitment to the budget policy: Poseidon(maxBudget, salt)
    // Same commitment regardless of validity — proves same policy was checked
    component hash = Poseidon(2);
    hash.inputs[0] <== maxBudget;
    hash.inputs[1] <== salt;
    commitmentHash <== hash.out;
}

component main = BudgetRangeProof(64);
