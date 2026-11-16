// The 7-trap decision checklist for Proof Gatekeeper.
//
// The platform wraps the condition fields in an `input` object inside the
// envelope; task_id stays at envelope level. This module flattens that and
// runs the checks in the tournament's order — the FIRST failing check is
// the reason_code. The ZK circuit enforces the same evaluation, so this
// must be a bit-exact mirror of it.
//
//   1. VK_SUBSTITUTION   proof_vk != registered_vk (lowercased)
//   2. PROOF_REUSED      proof_tx seen under a DIFFERENT task_id
//   3. THRESHOLD_MISMATCH  public_balance < minimum   (equality is VALID)
//   4. EXPIRED_CONDITION   current_block >= expiry_block (equality IS expired)
//   5. RECIPIENT_MISMATCH  recipient != condition_recipient (case-insensitive)
//   6. AMOUNT_OVERFLOW     amount > max_transfer (equality is VALID)
//   7. else VALID_CONDITION -> APPROVE
//
// Scoring note: a wrong APPROVE costs -6, a wrong REJECT -3, a missing
// proof -2. When in doubt, REJECT is the safer error. A malformed task
// (a field that cannot be read as a number, a missing key) throws — the
// HTTP layer turns that into a signed 500, never a crash.
//
// Proof-reuse tracking: one in-memory Map, proof_tx (lowercased) ->
// task_id, recorded on first sight. A retry of the SAME task_id with the
// same proof_tx is NOT reuse. A task with no proof_tx skips the check.

function createDecider() {
  const seenProofTx = new Map();

  // Decide one task envelope. Returns { decision, reason_code, fields }
  // where fields is the flattened task (strings, as received) for proving.
  // Throws on a malformed task.
  function decide(task) {
    if (!task || typeof task !== "object") {
      throw new Error("task envelope is not an object");
    }
    const input =
      task.input && typeof task.input === "object" && task.input !== null
        ? task.input
        : {};
    const fields = { ...input, task_id: task.task_id };

    // The decision needs every field present. A missing key is malformed,
    // not a trap — the caller reports it as a handler error.
    const required = [
      "registered_vk",
      "proof_vk",
      "minimum",
      "public_balance",
      "expiry_block",
      "current_block",
      "recipient",
      "condition_recipient",
      "amount",
      "max_transfer",
    ];
    for (const key of required) {
      if (fields[key] === undefined || fields[key] === null || fields[key] === "") {
        throw new Error(`missing task field: ${key}`);
      }
    }
    if (fields.task_id === undefined || fields.task_id === null || fields.task_id === "") {
      throw new Error("missing task field: task_id");
    }

    const proofTx =
      typeof fields.proof_tx === "string" && fields.proof_tx.length > 0
        ? fields.proof_tx.toLowerCase()
        : null;

    // Record on first sight, before any check runs.
    if (proofTx && !seenProofTx.has(proofTx)) {
      seenProofTx.set(proofTx, String(fields.task_id));
    }

    const reject = (reason_code) => ({ decision: "REJECT", reason_code, fields });

    // 1. VK_SUBSTITUTION
    if (String(fields.proof_vk).toLowerCase() !== String(fields.registered_vk).toLowerCase()) {
      return reject("VK_SUBSTITUTION");
    }

    // 2. PROOF_REUSED — same proof_tx under a different task_id.
    if (proofTx && seenProofTx.get(proofTx) !== String(fields.task_id)) {
      return reject("PROOF_REUSED");
    }

    // 3. THRESHOLD_MISMATCH — balance == minimum is valid.
    if (BigInt(fields.public_balance) < BigInt(fields.minimum)) {
      return reject("THRESHOLD_MISMATCH");
    }

    // 4. EXPIRED_CONDITION — strict: current == expiry IS expired.
    if (BigInt(fields.current_block) >= BigInt(fields.expiry_block)) {
      return reject("EXPIRED_CONDITION");
    }

    // 5. RECIPIENT_MISMATCH — case-insensitive.
    if (
      String(fields.recipient).toLowerCase() !==
      String(fields.condition_recipient).toLowerCase()
    ) {
      return reject("RECIPIENT_MISMATCH");
    }

    // 6. AMOUNT_OVERFLOW — amount == max is valid.
    if (BigInt(fields.amount) > BigInt(fields.max_transfer)) {
      return reject("AMOUNT_OVERFLOW");
    }

    // 7. Everything checks out.
    return { decision: "APPROVE", reason_code: "VALID_CONDITION", fields };
  }

  return { decide, seenProofTx };
}

module.exports = { createDecider };
