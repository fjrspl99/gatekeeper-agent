# Proof Gatekeeper agent — DECISION-ONLY

Deterministic HTTP agent for the zkVerify Agent Games **Proof Gatekeeper**
track. It receives signed task envelopes, runs the 7 documented checks,
and returns a signed APPROVE/REJECT decision. No LLM/model call is in the
decision path.

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
| `PORT` | no | default 3000 |
| `STATE_DIR` | no | default `./state` |

## Decision table (fixed order — first failure wins)

| # | Check | Fail → REJECT reason_code |
|---|---|---|
| 1 | `proof_vk == registered_vk` (case-insensitive) | `VK_SUBSTITUTION` |
| 2 | `public_balance >= minimum` (BigInt) | `THRESHOLD_MISMATCH` |
| 3 | `proof_tx` not in seen-set | `PROOF_REUSED` |
| 4 | `current_block <= expiry_block` | `EXPIRED_CONDITION` |
| 5 | `recipient == condition_recipient` (case-insensitive) | `RECIPIENT_MISMATCH` |
| 6 | `amount <= max_transfer` (BigInt) | `AMOUNT_OVERFLOW` |
| 7 | all pass | `APPROVE` / `VALID_CONDITION` |

Malformed input or any error → `REJECT` / `INVALID_TASK` (fail closed).
Boundary values are inclusive: balance == minimum, amount == max_transfer,
and block == expiry all APPROVE.

State: `state/seen.json` (every `proof_tx` processed) and
`state/decisions.json` (`task_id` → response, for idempotent retries).
Both persist across restarts — a seen-set that resets would approve a
reused proof.

## Scoring (decision-only)

A correct decision without a valid Groth16 proof scores **+10/task**
(+12 minus the −2 missing-proof penalty, no reliability bonus) instead of
+12 + bonus. Wrong decisions cost the same either way (−6 wrong approve,
−3 wrong reject). See `~/workspace/zkverify/NOTES.md` §3.

## NOT implemented yet — Groth16 proof

Proof generation is **blocked**: the guide publishes the circuit wasm/zkey
and `vk_hash`, but NOT the circuit's input signal names/values or the
public-signal order (gatekeeper nPublic = 13). To resolve: zkVerify
Discord, the agent dashboard after registration, or practice mode. Once
the inputs are known, add snarkjs proof generation + Kurier submit and
validate in practice mode before a scored round. Do **not** submit a
decision-only agent to a scored round expecting the reliability bonus.

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
