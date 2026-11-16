// Groth16 proving for the Gatekeeper circuit (snarkjs).
//
// Circuit inputs (13, names as the circuit declares them):
//   taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
//   conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash,
//   salt, decision
// Public signals (13): a salt-dependent binding hash first — the circuit
// computes Poseidon(salt, taskId) — then the 12 task fields (minus salt).
// The binding hash is produced by the circuit itself; this module only
// passes the inputs and returns whatever fullProve outputs.
//
// decision is "1" for APPROVE, "0" for REJECT. The circuit asserts the
// decision equals the AND of its five field checks, so a proof can only
// be generated for a decision the circuit agrees with — feed it a wrong
// decision and fullProve throws. That is the fail-closed behaviour we want:
// the caller then answers with the decision and no proof instead of hanging.
//
// salt is a fresh random 32 bytes per proof ("0x" + 64 hex chars) and stays
// private; it is what makes each proof unique to its task.

const crypto = require("node:crypto");
const snarkjs = require("snarkjs");
const { toField, taskIdToField } = require("../lib/field");

// Build the circuit input object for one decided task.
// Throws on a field that cannot be mapped (malformed task).
function buildCircuitInput(fields, decision, taskIdMode) {
  return {
    taskId: taskIdToField(fields.task_id, taskIdMode).toString(),
    minimum: toField(fields.minimum).toString(),
    publicBalance: toField(fields.public_balance).toString(),
    expiryBlock: toField(fields.expiry_block).toString(),
    currentBlock: toField(fields.current_block).toString(),
    recipient: toField(fields.recipient).toString(),
    conditionRecipient: toField(fields.condition_recipient).toString(),
    amount: toField(fields.amount).toString(),
    maxTransfer: toField(fields.max_transfer).toString(),
    registeredVkHash: toField(fields.registered_vk).toString(),
    proofVkHash: toField(fields.proof_vk).toString(),
    salt: toField("0x" + crypto.randomBytes(32).toString("hex")).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
  };
}

// Generate a Groth16 proof for a decided task. Returns
// { proof, publicSignals }. Throws when the circuit refuses the decision
// (wrong decision for the inputs) or the artifacts are unreadable.
async function generateProof(fields, decision, { wasmPath, zkeyPath, taskIdMode }) {
  const input = buildCircuitInput(fields, decision, taskIdMode);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );
  return { proof, publicSignals };
}

// Load the verification key out of the zkey (needed to verify locally).
async function loadVerificationKey(zkeyPath) {
  return snarkjs.zKey.exportVerificationKey(zkeyPath);
}

// Verify a proof against its public signals with a verification key.
async function verifyProof(publicSignals, proof, verificationKey) {
  return snarkjs.groth16.verify(verificationKey, publicSignals, proof);
}

module.exports = { buildCircuitInput, generateProof, loadVerificationKey, verifyProof };
