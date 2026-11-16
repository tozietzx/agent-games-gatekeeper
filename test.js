// Tests for the Proof Gatekeeper. Run with: npm test
//
// (a) The 7-trap checklist plus every boundary case:
//     balance == minimum is valid; current == expiry is expired;
//     amount == max is valid; a same-task retry is not reuse; proof reuse
//     under another task is rejected.
// (b) A REAL Groth16 proof for an APPROVE task and for a REJECT task,
//     each verified locally with snarkjs — plus the fail-closed property
//     that the circuit refuses a wrong decision.
//
// Note: snarkjs leaves the Node event loop alive after use, so this file
// calls process.exit() explicitly at the end.

const assert = require("node:assert/strict");
const path = require("node:path");

const { createDecider } = require("./gatekeeper/decide");
const {
  generateProof,
  loadVerificationKey,
  verifyProof,
} = require("./gatekeeper/prove");
const { toField, taskIdToField, REGISTERED_VK_HASH } = require("./lib/field");
const hmac = require("./lib/hmac");

const WASM_PATH = path.join(__dirname, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "circuits", "gatekeeper_final.zkey");

let passed = 0;
function check(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok - ${name}`);
}
async function checkAsync(name, fn) {
  await fn();
  passed += 1;
  console.log(`  ok - ${name}`);
}

// A valid task envelope; overrides replace individual input fields.
function makeTask(overrides = {}, taskId = "t1", proofTx = "0xaaa111") {
  return {
    task_id: taskId,
    input: {
      registered_vk: REGISTERED_VK_HASH,
      proof_vk: REGISTERED_VK_HASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: "8430000",
      current_block: "8420000",
      recipient: "12345",
      condition_recipient: "12345",
      amount: "500",
      max_transfer: "1000",
      proof_tx: proofTx,
      ...overrides,
    },
  };
}

async function main() {
  console.log("== decision: traps and boundaries ==");

  check("valid task approves (VALID_CONDITION)", () => {
    const { decide } = createDecider();
    const r = decide(makeTask());
    assert.equal(r.decision, "APPROVE");
    assert.equal(r.reason_code, "VALID_CONDITION");
  });

  check("VK_SUBSTITUTION rejects when proof_vk differs", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ proof_vk: "0xdeadbeef" }));
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "VK_SUBSTITUTION");
  });

  check("VK comparison is case-insensitive", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ proof_vk: REGISTERED_VK_HASH.toUpperCase() }));
    assert.equal(r.decision, "APPROVE");
  });

  check("THRESHOLD_MISMATCH rejects balance below minimum", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ public_balance: "999" }));
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "THRESHOLD_MISMATCH");
  });

  check("boundary: balance == minimum is VALID", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ public_balance: "1000" }));
    assert.equal(r.decision, "APPROVE");
    assert.equal(r.reason_code, "VALID_CONDITION");
  });

  check("EXPIRED_CONDITION rejects current block past expiry", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ current_block: "8430001" }));
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "EXPIRED_CONDITION");
  });

  check("boundary: current == expiry IS expired", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ current_block: "8430000" }));
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "EXPIRED_CONDITION");
  });

  check("RECIPIENT_MISMATCH rejects a different recipient", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ recipient: "99999" }));
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "RECIPIENT_MISMATCH");
  });

  check("recipient comparison is case-insensitive", () => {
    const { decide } = createDecider();
    const r = decide(
      makeTask({ recipient: "0xABCDEF", condition_recipient: "0xabcdef" })
    );
    assert.equal(r.decision, "APPROVE");
  });

  check("AMOUNT_OVERFLOW rejects amount above max", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ amount: "1001" }));
    assert.equal(r.decision, "REJECT");
    assert.equal(r.reason_code, "AMOUNT_OVERFLOW");
  });

  check("boundary: amount == max is VALID", () => {
    const { decide } = createDecider();
    const r = decide(makeTask({ amount: "1000" }));
    assert.equal(r.decision, "APPROVE");
    assert.equal(r.reason_code, "VALID_CONDITION");
  });

  check("first failing check wins (VK before threshold)", () => {
    const { decide } = createDecider();
    const r = decide(
      makeTask({ proof_vk: "0xdeadbeef", public_balance: "1" })
    );
    assert.equal(r.reason_code, "VK_SUBSTITUTION");
  });

  check("first failing check wins (threshold before expiry)", () => {
    const { decide } = createDecider();
    const r = decide(
      makeTask({ public_balance: "1", current_block: "99999999" })
    );
    assert.equal(r.reason_code, "THRESHOLD_MISMATCH");
  });

  check("PROOF_REUSED rejects the same proof_tx under another task", () => {
    const { decide } = createDecider();
    const first = decide(makeTask({}, "task-a", "0xreuse1"));
    assert.equal(first.decision, "APPROVE");
    const second = decide(makeTask({}, "task-b", "0xreuse1"));
    assert.equal(second.decision, "REJECT");
    assert.equal(second.reason_code, "PROOF_REUSED");
  });

  check("same-task retry with the same proof_tx is NOT reuse", () => {
    const { decide } = createDecider();
    const first = decide(makeTask({}, "task-a", "0xreuse2"));
    assert.equal(first.decision, "APPROVE");
    const retry = decide(makeTask({}, "task-a", "0xreuse2"));
    assert.equal(retry.decision, "APPROVE");
    assert.equal(retry.reason_code, "VALID_CONDITION");
  });

  check("proof_tx matching is case-insensitive", () => {
    const { decide } = createDecider();
    decide(makeTask({}, "task-a", "0xAbC123"));
    const r = decide(makeTask({}, "task-b", "0XABC123"));
    assert.equal(r.reason_code, "PROOF_REUSED");
  });

  check("a task with no proof_tx skips the reuse check", () => {
    const { decide } = createDecider();
    const task = makeTask();
    delete task.input.proof_tx;
    const r = decide(task);
    assert.equal(r.decision, "APPROVE");
  });

  check("malformed task throws (missing field)", () => {
    const { decide } = createDecider();
    const task = makeTask();
    delete task.input.minimum;
    assert.throws(() => decide(task), /missing task field: minimum/);
  });

  check("malformed task throws (non-numeric balance)", () => {
    const { decide } = createDecider();
    assert.throws(() => decide(makeTask({ public_balance: "abc" })));
  });

  check("fields wrapped in input, not flat on the envelope", () => {
    // A task with the fields flat at envelope level (no `input`) is
    // malformed per the protocol — the platform always wraps them.
    const { decide } = createDecider();
    const flat = { task_id: "t1", minimum: "1000" };
    assert.throws(() => decide(flat), /missing task field/);
  });

  console.log("== hmac: sign and verify ==");
  check("sign/verify round-trips (hex format)", () => {
    const secret = "test-secret";
    const body = Buffer.from('{"a":1}', "utf8");
    const sig = hmac.sign(secret, body, "hex");
    assert.equal(hmac.verify(secret, body, sig), true);
    assert.equal(hmac.verify(secret, body, sig + "0"), false);
    assert.equal(hmac.verify(secret, Buffer.from('{"a":2}', "utf8"), sig), false);
  });

  check("sign/verify round-trips (sha256= format)", () => {
    const secret = "test-secret";
    const body = Buffer.from("hello", "utf8");
    const sig = hmac.sign(secret, body, "sha256=");
    assert.ok(sig.startsWith("sha256="));
    assert.equal(hmac.verify(secret, body, sig), true);
  });

  check("taskId mapping: keccak is the default and is deterministic", () => {
    const a = taskIdToField("gk_24_9d1", "keccak");
    const b = taskIdToField("gk_24_9d1", "keccak");
    assert.equal(a, b);
    assert.ok(a > 0n);
    assert.notEqual(taskIdToField("gk_24_9d1", "numeric"), a);
    assert.equal(taskIdToField("gk_24_9d1", "numeric"), 2491n);
    assert.equal(taskIdToField("gk_24_9d1", "hex"), 0x249d1n);
  });

  console.log("== proofs: real Groth16, verified locally ==");
  const vk = await loadVerificationKey(ZKEY_PATH);

  await checkAsync("APPROVE proof generates and verifies", async () => {
    const { decide } = createDecider();
    const { decision, fields } = decide(makeTask({}, "proof-ok-1", "0xproof1"));
    assert.equal(decision, "APPROVE");
    const { proof, publicSignals } = await generateProof(fields, decision, {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      taskIdMode: "keccak",
    });
    assert.equal(publicSignals.length, 13);
    // Public signals: [binding, registeredVkHash, proofVkHash, minimum,
    // publicBalance, expiryBlock, currentBlock, recipient,
    // conditionRecipient, amount, maxTransfer, decision, taskId].
    assert.equal(publicSignals[1], toField(REGISTERED_VK_HASH).toString());
    assert.equal(publicSignals[2], toField(REGISTERED_VK_HASH).toString());
    assert.equal(publicSignals[3], "1000");
    assert.equal(publicSignals[4], "1460");
    assert.equal(publicSignals[11], "1");
    assert.equal(publicSignals[12], taskIdToField("proof-ok-1", "keccak").toString());
    assert.equal(await verifyProof(publicSignals, proof, vk), true);
  });

  await checkAsync("REJECT proof generates and verifies", async () => {
    const { decide } = createDecider();
    const { decision, reason_code, fields } = decide(
      makeTask({ amount: "1500" }, "proof-no-1", "0xproof2")
    );
    assert.equal(decision, "REJECT");
    assert.equal(reason_code, "AMOUNT_OVERFLOW");
    const { proof, publicSignals } = await generateProof(fields, decision, {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      taskIdMode: "keccak",
    });
    assert.equal(publicSignals.length, 13);
    assert.equal(publicSignals[9], "1500");
    assert.equal(publicSignals[10], "1000");
    assert.equal(publicSignals[11], "0");
    assert.equal(await verifyProof(publicSignals, proof, vk), true);
  });

  await checkAsync("same task, two proofs: only the binding hash changes", async () => {
    const { decide } = createDecider();
    const { decision, fields } = decide(makeTask({}, "proof-ok-2", "0xproof3"));
    const a = await generateProof(fields, decision, {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      taskIdMode: "keccak",
    });
    const b = await generateProof(fields, decision, {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      taskIdMode: "keccak",
    });
    // Fresh random salt each time -> a different binding hash ...
    assert.notEqual(a.publicSignals[0], b.publicSignals[0]);
    // ... but the 12 task fields are identical.
    assert.deepEqual(a.publicSignals.slice(1), b.publicSignals.slice(1));
    assert.equal(await verifyProof(a.publicSignals, a.proof, vk), true);
    assert.equal(await verifyProof(b.publicSignals, b.proof, vk), true);
  });

  await checkAsync("circuit refuses a wrong decision (fail-closed)", async () => {
    const { decide } = createDecider();
    const { fields } = decide(makeTask({}, "proof-bad-1", "0xproof4"));
    // The task is valid, so proving it as REJECT must fail inside the
    // circuit — a wrong answer cannot be dressed up as a proven one.
    await assert.rejects(
      generateProof(fields, "REJECT", {
        wasmPath: WASM_PATH,
        zkeyPath: ZKEY_PATH,
        taskIdMode: "keccak",
      })
    );
  });

  console.log(`\nALL TESTS PASSED (${passed} checks)`);
  process.exit(0);
}

main().catch((err) => {
  console.error("\nTEST FAILURE:", err);
  process.exit(1);
});
