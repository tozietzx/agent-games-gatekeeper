# agent-games-gatekeeper

Proof Gatekeeper agent for **zkVerify Agent Games, Season 01** (handle:
`aspjawir`). A public HTTPS endpoint: the platform sends it a signed
payment-condition task, and within 60 seconds it answers one word —
APPROVE or REJECT — plus a Groth16 proof that the decision follows the
rules. The platform re-verifies the proof instead of trusting the answer.

Stack: plain Node.js, no framework, stdlib HTTP only. Dependencies:
`snarkjs` (Groth16) and `js-sha3` (keccak256 for the task-id mapping).

## How it works

1. **HMAC first.** Every inbound POST is verified against the
   `x-agent-games-signature` header over the *raw* request body bytes,
   before JSON parsing. A bad or missing signature is a signed 401.
   Every response is signed the same way.
2. **Decide.** The task envelope wraps the condition fields in an
   `input` object; `task_id` stays at envelope level. The 7-trap
   checklist runs in order and the first failure is the reason:
   1. `VK_SUBSTITUTION` — `proof_vk` != `registered_vk` (lowercased)
   2. `PROOF_REUSED` — `proof_tx` already seen under a *different*
      `task_id` (a retry of the same task is not reuse; tracked in
      memory, `proof_tx` lowercased → `task_id`)
   3. `THRESHOLD_MISMATCH` — `public_balance < minimum`
      (balance == minimum is valid)
   4. `EXPIRED_CONDITION` — `current_block >= expiry_block`
      (equality *is* expired)
   5. `RECIPIENT_MISMATCH` — `recipient` != `condition_recipient`
      (case-insensitive)
   6. `AMOUNT_OVERFLOW` — `amount > max_transfer`
      (amount == max is valid)
   7. otherwise `VALID_CONDITION` → APPROVE
3. **Prove.** The decision is proven with the tournament's official
   Groth16 circuit (`gatekeeper.wasm` / `gatekeeper_final.zkey`).
   Circuit inputs (13): `taskId, minimum, publicBalance, expiryBlock,
   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
   registeredVkHash, proofVkHash, salt, decision` (`"1"` = APPROVE,
   `"0"` = REJECT). Public signals (13): a salt-dependent binding hash
   first — the circuit computes `Poseidon(salt, taskId)` — then the 12
   task fields. The circuit asserts the decision equals the AND of its
   five field checks, so a wrong decision cannot be proven at all
   (proof generation throws; the server then answers with the decision
   and no proof, plus `proof_error`, instead of hanging). `PROOF_REUSED`
   answers carry no proof by design: the circuit has no memory of other
   tasks. `taskId` maps to a field element as `keccak256(utf8(task_id))
   mod p` by default (see `GATEKEEPER_TASK_ID_MODE`).
4. **Self-test.** On startup the server decides a synthetic valid task,
   generates a real proof, and verifies it locally. `GET /health`
   reports `selfTest: "PASS"`, `"FAIL (<reason>)"`, or `"pending"`.

Scoring (for context): correct +12, wrong APPROVE −6, wrong REJECT −3,
timeout / missing proof −2, reliability bonus +0..+5. When in doubt,
REJECT is the safer error.

## Run

```bash
npm install
npm test          # 27 checks: all 7 traps + boundaries, real APPROVE and
                  # REJECT proofs verified locally with snarkjs
npm start         # listens on $PORT (default 8080)
```

Circuit artifacts are downloaded at boot if missing (from
`agentgames.zkverify.io/circuits/`); a failed download exits non-zero.
They are never committed — see `.gitignore`.

## Endpoints

- `GET /health` → `{ ok, agent: "proof-gatekeeper", hmacConfigured,
  taskIdMode, selfTest }` (signed)
- `POST /gatekeeper` → task envelope in, `{ decision, reason_code,
  proof_tx?, proof?, public_signals? }` out (signed). A preflight body
  (`{ type: "agent-games.preflight.v1" }`) gets
  `{ ok: true, protocolVersion: "v1" }`.
- Errors are signed too: 401 bad signature, 400 bad JSON, 404 unknown
  route, 500 handler error (malformed task — never a crash).

## Environment

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `8080` | |
| `HOST` | `0.0.0.0` | |
| `AGENT_GAMES_HMAC_SECRET` | — | Issued by the dashboard at registration. Without it, responses are unsigned and inbound checks are skipped (with a boot warning). |
| `AGENT_GAMES_HMAC_FORMAT` | `hex` | Or `sha256=` (header value becomes `sha256=<hex>`). Inbound accepts both spellings. |
| `GATEKEEPER_TASK_ID_MODE` | `keccak` | Or `numeric` (digits of the id) / `hex` (hex chars of the id), each mod p. |

Copy `.env.example` to `.env` for local runs. Never commit `.env`.

## Deploy to Railway (from GitHub)

1. Push this repo to GitHub (public repo on the account that registers
   the agent — the dashboard requires a personal-account repo URL).
2. In Railway: New Project → Deploy from GitHub repo. No build step is
   needed (`npm start` runs `node server.js`); set the start command to
   `npm start` if Railway does not pick it up.
3. Add the variables: `AGENT_GAMES_HMAC_SECRET` (the secret the
   dashboard issued for this agent), `GATEKEEPER_TASK_ID_MODE=keccak`.
   `PORT` is set by Railway automatically. **Apply / deploy the change**
   after adding a variable — a staged variable is not live until the
   redeploy lands (verify from the server side: `GET /health` must show
   `hmacConfigured: true`).
4. Keep the service awake (Railway Serverless off / no sleep): an
   offline agent forfeits tasks. The circuit files download on first
   boot; later boots reuse them.
5. Register the public endpoint (e.g.
   `https://<app>.up.railway.app/gatekeeper`) in the Agent Games
   dashboard, then run the dashboard's preflight / practice dispatch
   and confirm it reports healthy.

## Status

- Proof Gatekeeper only. Steal the VFY is out of scope for this build.
- Season 01 runs 21 Oct – 21 Nov 2026; registration closes
  21 Nov 2026, 22:00 UTC.
- Local verification (16 Nov 2026): `npm test` — ALL TESTS PASSED
  (27 checks); live server on a local port — `GET /health` selfTest
  PASS, preflight returns protocol v1, a signed valid task answers
  APPROVE/VALID_CONDITION in ~370 ms with a proof that verifies locally;
  bad signature → 401, bad JSON → 400, unknown route → 404.
