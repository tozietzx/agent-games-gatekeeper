// Proof Gatekeeper — Agent Games Season 01 (handle: aspjawir).
//
// A plain Node.js HTTP server, stdlib only. The platform sends signed task
// envelopes to POST /gatekeeper; this server answers APPROVE or REJECT plus
// a Groth16 proof of that decision, all within 60 seconds.
//
//   GET  /health      -> { ok, agent, hmacConfigured, taskIdMode, selfTest }
//   POST /gatekeeper  -> task envelope in, decision + proof out
//   POST (any path) with body.type === "agent-games.preflight.v1"
//                      -> { ok: true, protocolVersion: "v1" }
//
// Every response is signed with HMAC-SHA256 over the raw response body
// (header x-agent-games-signature) when AGENT_GAMES_HMAC_SECRET is set.
// Every inbound POST is verified the same way, over the RAW body bytes,
// before JSON parsing. A missing secret disables both directions and logs
// a warning.
//
// Environment:
//   PORT (8080)  HOST (0.0.0.0)
//   AGENT_GAMES_HMAC_SECRET    (no default — required in production)
//   AGENT_GAMES_HMAC_FORMAT    "hex" (default) or "sha256="
//   GATEKEEPER_TASK_ID_MODE    "keccak" (default), "numeric", or "hex"
//
// Circuit artifacts (gatekeeper.wasm, gatekeeper_final.zkey) are downloaded
// at boot if missing; a failed download exits non-zero. They are never
// committed to git.

const http = require("node:http");
const path = require("node:path");

const hmac = require("./lib/hmac");
const { REGISTERED_VK_HASH } = require("./lib/field");
const { createDecider } = require("./gatekeeper/decide");
const {
  generateProof,
  loadVerificationKey,
  verifyProof,
} = require("./gatekeeper/prove");
const { fetchCircuits, CIRCUITS_DIR } = require("./scripts/fetch-circuits");

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || "hex";
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || "keccak";

const WASM_PATH = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");

// A task is at most a few hundred bytes of JSON; 1 MB is a generous cap
// against abusive bodies.
const MAX_BODY_BYTES = 1024 * 1024;

const PREFLIGHT_TYPE = "agent-games.preflight.v1";

// The self-test runs once, asynchronously, after the server starts
// listening. /health reports "pending" until it finishes.
let selfTestState = "pending";

const decider = createDecider();

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

// Send a JSON response, signed when a secret is configured.
function sendJson(res, statusCode, obj) {
  const body = Buffer.from(JSON.stringify(obj), "utf8");
  const headers = { "content-type": "application/json" };
  if (HMAC_SECRET) {
    headers[hmac.SIGNATURE_HEADER] = hmac.sign(HMAC_SECRET, body, HMAC_FORMAT);
  }
  res.writeHead(statusCode, headers);
  res.end(body);
}

// Read the raw request body as a Buffer (needed for HMAC over raw bytes).
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let tooLarge = false;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) reject(new Error("body too large"));
      else resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

// Handle one POST /gatekeeper task. Never throws: every failure path is a
// signed JSON response.
async function handleGatekeeper(task) {
  let result;
  try {
    result = decider.decide(task);
  } catch (err) {
    log("[gatekeeper] malformed task:", err.message);
    return { status: 500, body: { ok: false, error: "handler error" } };
  }

  const { decision, reason_code, fields } = result;
  const body = { decision, reason_code };
  if (typeof fields.proof_tx === "string" && fields.proof_tx.length > 0) {
    body.proof_tx = fields.proof_tx;
  }

  // PROOF_REUSED carries no proof: the circuit cannot express reuse (it
  // has no memory of other tasks), so a proof for it would fail anyway,
  // and the platform excludes reuse answers from the reliability bonus.
  if (reason_code === "PROOF_REUSED") {
    log(`[gatekeeper] task=${fields.task_id} decision=REJECT reason=PROOF_REUSED (no proof)`);
    return { status: 200, body };
  }

  try {
    const { proof, publicSignals } = await generateProof(fields, decision, {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      taskIdMode: TASK_ID_MODE,
    });
    body.proof = proof;
    body.public_signals = publicSignals;
    log(
      `[gatekeeper] task=${fields.task_id} decision=${decision} reason=${reason_code} proof=ok`
    );
  } catch (err) {
    // A visible -2 beats a hang: answer with the decision and no proof.
    log(
      `[gatekeeper] task=${fields.task_id} decision=${decision} reason=${reason_code} proof FAILED: ${err.message}`
    );
    body.proof_error = "proof generation failed";
  }
  return { status: 200, body };
}

// Startup self-test: a synthetic VALID task, decided, proven, and verified
// locally. Sets selfTestState to "PASS" or "FAIL (<reason>)".
async function runSelfTest() {
  const task = {
    task_id: "selftest_1",
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
      proof_tx: "0xselftest",
    },
  };
  try {
    const result = decider.decide(task);
    if (result.decision !== "APPROVE" || result.reason_code !== "VALID_CONDITION") {
      throw new Error(`unexpected self-test decision: ${result.decision}/${result.reason_code}`);
    }
    const { proof, publicSignals } = await generateProof(result.fields, "APPROVE", {
      wasmPath: WASM_PATH,
      zkeyPath: ZKEY_PATH,
      taskIdMode: TASK_ID_MODE,
    });
    const vk = await loadVerificationKey(ZKEY_PATH);
    const ok = await verifyProof(publicSignals, proof, vk);
    if (!ok) throw new Error("self-test proof did not verify locally");
    selfTestState = "PASS";
    log("[self-test] PASS");
  } catch (err) {
    selfTestState = `FAIL (${err.message})`;
    log(`[self-test] ${selfTestState}`);
  }
}

async function main() {
  // Circuits first: without them there is nothing to prove with.
  try {
    await fetchCircuits();
  } catch (err) {
    console.error(`[boot] circuit download failed: ${err.message}`);
    process.exit(1);
  }

  if (!HMAC_SECRET) {
    log("[boot] WARNING: AGENT_GAMES_HMAC_SECRET is not set — responses will be unsigned and inbound HMAC checks are skipped");
  }

  const server = http.createServer((req, res) => {
    (async () => {
      const url = new URL(req.url, "http://localhost");
      const pathname = url.pathname;

      if (req.method === "GET" && pathname === "/health") {
        sendJson(res, 200, {
          ok: true,
          agent: "proof-gatekeeper",
          hmacConfigured: Boolean(HMAC_SECRET),
          taskIdMode: TASK_ID_MODE,
          selfTest: selfTestState,
        });
        return;
      }

      if (req.method === "POST") {
        let rawBody;
        try {
          rawBody = await readRawBody(req);
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message || "invalid body" });
          return;
        }

        // HMAC over the RAW bytes, before any JSON parsing.
        if (HMAC_SECRET && !hmac.verify(HMAC_SECRET, rawBody, req.headers[hmac.SIGNATURE_HEADER])) {
          sendJson(res, 401, { ok: false, error: "bad signature" });
          return;
        }

        let body;
        try {
          body = JSON.parse(rawBody.toString("utf8"));
        } catch {
          sendJson(res, 400, { ok: false, error: "invalid json" });
          return;
        }

        // Preflight: the platform's protocol handshake, on any POST path.
        if (body && body.type === PREFLIGHT_TYPE) {
          sendJson(res, 200, { ok: true, protocolVersion: "v1" });
          return;
        }

        if (pathname === "/gatekeeper") {
          const { status, body: out } = await handleGatekeeper(body);
          sendJson(res, status, out);
          return;
        }

        sendJson(res, 404, { ok: false, error: "not found" });
        return;
      }

      sendJson(res, 404, { ok: false, error: "not found" });
    })().catch((err) => {
      log("[server] unexpected error:", err);
      try {
        sendJson(res, 500, { ok: false, error: "handler error" });
      } catch {
        // Response already gone; nothing left to do.
      }
    });
  });

  server.listen(PORT, HOST, () => {
    log(`[boot] proof-gatekeeper listening on http://${HOST}:${PORT}`);
    log(`[boot] taskIdMode=${TASK_ID_MODE} hmacFormat=${HMAC_FORMAT} hmacConfigured=${Boolean(HMAC_SECRET)}`);
    // Self-test runs after listen so /health is up while it proves.
    runSelfTest();
  });
}

main();
