# Proof Gatekeeper agent — WITH Groth16 proofs

Deterministic HTTP agent for the zkVerify Agent Games **Proof Gatekeeper**
track. It receives signed task envelopes, runs the 7 documented checks,
generates a Groth16 proof for each decision with snarkjs (circuit
artifacts in `./circuit`, mapping verified locally 2026-11-17 — see
`~/workspace/zkverify/circuit/MAPPING.md`), optionally submits the proof
to Kurier for on-chain confirmation, and returns a signed
APPROVE/REJECT decision + proof. No LLM/model call is in the decision path.

## Run

```bash
cp .env.example .env   # then fill in AGENT_GAMES_HMAC_SECRET from the dashboard
node server.mjs
```

- `POST /agent` — task + preflight handler (also accepts `POST /`)
- `GET /` and `GET /health` — health check, `{"ok": true}`
- Listens on `127.0.0.1:$PORT` (default 3000). Expose it with the
  Cloudflare Tunnel in `~/workspace/zkverify/` (see NOTES.md) — the
  platform requires a public `https://` URL, no custom ports.

## Env

| Var | Required | Notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes, for production | 32-byte secret generated at endpoint registration (dashboard, shown once). If unset, the server runs in **UNSAFE dev mode**: HMAC verification is disabled and responses are unsigned. Never register an endpoint in dev mode. |
| `KURIER_API_KEY` | no | Free key from kurier.xyz — enables on-chain confirmation. Without it the agent still answers with a valid in-response proof, but scored rounds may not count it as verified (see Scoring). |
| `KURIER_API_URL` | no | default https://api.kurier.xyz/api/v1 |
| `KURIER_POLL_BUDGET_MS` | no | default 40000 — bounded so the answer stays inside the 60 s task window |
| `PORT` | no | default 3000 |
| `STATE_DIR` | no | default `./state` |

## Decision table (fixed order — first failure wins)

| # | Check | Fail → REJECT reason_code |
|---|---|---|
| 1 | `proof_vk == registered_vk` (case-insensitive) | `VK_SUBSTITUTION` |
| 2 | `public_balance >= minimum` (BigInt) | `THRESHOLD_MISMATCH` |
| 3 | `proof_tx` not in seen-set | `PROOF_REUSED` |
| 4 | `current_block < expiry_block` (STRICT: == is expired, circuit-verified) | `EXPIRED_CONDITION` |
| 5 | `recipient == condition_recipient` (case-insensitive) | `RECIPIENT_MISMATCH` |
| 6 | `amount <= max_transfer` (BigInt) | `AMOUNT_OVERFLOW` |
| 7 | all pass | `APPROVE` / `VALID_CONDITION` |

Malformed input or any error → `REJECT` / `INVALID_TASK` (fail closed).
Boundary values are inclusive, except expiry: balance == minimum and
amount == max_transfer APPROVE, but block == expiry REJECTS (the circuit
treats current_block >= expiry_block as expired — verified 2026-11-17).

State: `state/seen.json` (every `proof_tx` processed) and
`state/decisions.json` (`task_id` → response, for idempotent retries).
Both persist across restarts — a seen-set that resets would approve a
reused proof.

## Scoring (with Groth16 proofs)

A correct decision with a valid Groth16 proof scores **+12/task** plus
the reliability bonus (verified proofs / tasks), instead of +10
decision-only (+12 minus the −2 missing-proof penalty, no bonus).
Wrong decisions cost the same either way (−6 wrong approve, −3 wrong
reject). In scored rounds the platform counts a proof as verified only
when it is CONFIRMED ON-CHAIN — see Kurier below. See
`~/workspace/zkverify/NOTES.md` §3.

## Groth16 proof — IMPLEMENTED 2026-11-17

Circuit input mapping reverse-engineered from community sources and
verified locally with snarkjs (see `~/workspace/zkverify/circuit/MAPPING.md`):
13 inputs, taskId = keccak256(task_id) mod p, fresh random salt per proof,
decision 1/0. `node test.mjs` verifies every returned proof with
`groth16.verify` against the circuit vk (17/17 PASS, proof gen ~0.3–0.9 s).

Kurier (on-chain confirmation): when `KURIER_API_KEY` is set, each proof
is submitted to Kurier and polled until Finalized (bounded 40 s budget);
the response's `proof_tx` then carries the Kurier tx hash. Evidence from
andruu's Round 3 (0/8 proofs counted with in-response proofs only) says
this step is what makes proofs count in scored rounds. **Kurier key still
missing — free signup at kurier.xyz.** Without it the agent answers with
valid in-response proofs only.

## Assumptions to confirm in practice mode

1. **HMAC signature encoding.** The guide does not publish it. The agent
   verifies `x-agent-games-signature` as hex (optionally `sha256=<hex>`)
   or base64 of HMAC-SHA256 over the raw body, and signs responses the
   same way (raw hex). If practice rejects the signature, check the
   dashboard/docs for the exact encoding.
2. **Response shape.** The event page's example echoes `proof_tx`
   (`{decision, reason_code, proof_tx}`); the starter prompt's shape is
   `{decision, reason_code, proof, public_signals}`. This agent returns
   the event-page shape (with `proof_tx`); `proof`/`public_signals` are
   added when proof generation lands.
3. **APPROVE reason_code.** The valid case is labelled `VALID_CONDITION`
   in the trap encyclopedia; the guide never shows an APPROVE response
   example. Confirm in practice mode.
4. **Seen-set semantics.** The agent records *every* `proof_tx` it
   processes as seen (even if that task was rejected for another trap),
   on the reading that "already accepted" means "used in a previous
   task". A platform retry of the same `task_id` returns the cached
   response and is never flagged as reuse. If practice shows the
   platform only counts *approved* proofs as "accepted", narrow the
   recording to approved tasks only.
5. **Preflight.** Responds `{ok: true, protocolVersion: "v1"}`, signed,
   to `{"type": "agent-games.preflight.v1", ...}` on the same endpoint.

## Test

```bash
node test.mjs   # spawns the server with a test secret, replays all cases
```

Covers: health, preflight, bad/missing HMAC (401), all 7 decision cases,
boundary values, PROOF_REUSED, idempotent replay, malformed input, and
seen-set persistence across a restart.
