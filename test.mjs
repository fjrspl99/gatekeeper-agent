// Test harness for the Proof Gatekeeper decision-only agent.
// Spawns server.mjs as a child (test secret, temp state dir), replays
// sample envelopes for all 7 decision cases + idempotency + bad HMAC +
// preflight + health + cross-restart persistence of the seen-set.
// Usage: node test.mjs        (exit 0 = all PASS, non-zero = any FAIL)
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SECRET = "test-secret-32-bytes-long-0123456789";
const PORT = 3456;
const BASE = `http://127.0.0.1:${PORT}`;
const STATE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "gk-test-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const VK_REG = "0x7d3a9c1e4f2a8b6d5e0c1a2b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
const VK_OTHER = "0xa4c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3";
const ADDR = "0xDe42a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8";
const ADDR_OTHER = "0xBeef1111222233334444555566667777888899990000";

function task(taskId, proofTx, overrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: "2026-11-14T10:00:00Z",
    deadline_at: "2026-11-14T10:01:00Z",
    input: {
      registered_vk: VK_REG,
      proof_vk: VK_REG,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: "500",
      max_transfer: "1000",
      proof_tx: proofTx,
      ...overrides,
    },
  };
}
const tx = (n) => "0xa4c18ff1" + String(n).padStart(56, "0");

let server = null;
async function startServer() {
  server = spawn("node", ["server.mjs"], {
    cwd: path.dirname(new URL(import.meta.url).pathname),
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, STATE_DIR },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout.on("data", (d) => process.stdout.write("[srv] " + d));
  server.stderr.on("data", (d) => process.stdout.write("[srv:err] " + d));
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error("server did not come up");
}
async function stopServer() {
  if (!server) return;
  server.kill("SIGTERM");
  await new Promise((r) => server.on("exit", r));
  server = null;
}

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}
async function postTask(envelope, { badSig = false, noSig = false } = {}) {
  const body = JSON.stringify(envelope);
  const headers = { "content-type": "application/json" };
  if (!noSig) headers["x-agent-games-signature"] = badSig ? "deadbeef" : sign(body);
  const r = await fetch(`${BASE}/agent`, { method: "POST", headers, body });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep null */ }
  const respSig = r.headers.get("x-agent-games-signature");
  const sigOk = respSig ? respSig === sign(text) : false;
  return { status: r.status, json, sigOk, hasSig: !!respSig };
}

let pass = 0, fail = 0;
function check(name, cond, detail = "") {
  if (cond) { pass++; console.log(`PASS  ${name}`); }
  else { fail++; console.log(`FAIL  ${name}  ${detail}`); }
}

try {
  await startServer();

  // 1. Health
  const h = await fetch(`${BASE}/`);
  check("GET / health 200 {ok:true}", h.ok && (await h.json()).ok === true);

  // 2. Preflight (signed request, signed response)
  const pfBody = JSON.stringify({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: "2026-11-14T10:00:00Z", nonce: "abc123" });
  const pf = await fetch(`${BASE}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(pfBody) },
    body: pfBody,
  });
  const pfJson = await pf.json();
  check("preflight -> {ok:true, protocolVersion:v1}",
    pf.status === 200 && pfJson.ok === true && pfJson.protocolVersion === "v1",
    JSON.stringify(pfJson));

  // 3. Bad HMAC -> 401
  const bad = await postTask(task("gk_bad", tx(90)), { badSig: true });
  check("bad HMAC -> 401", bad.status === 401, `status=${bad.status}`);

  // 4. Missing signature -> 401
  const nosig = await postTask(task("gk_nosig", tx(91)), { noSig: true });
  check("missing signature -> 401", nosig.status === 401, `status=${nosig.status}`);

  // 5-10. The 7 decision cases (each with a fresh proof_tx)
  const cases = [
    ["VALID_CONDITION -> APPROVE", task("gk_01", tx(1)), "APPROVE", "VALID_CONDITION"],
    ["VK_SUBSTITUTION -> REJECT", task("gk_02", tx(2), { proof_vk: VK_OTHER }), "REJECT", "VK_SUBSTITUTION"],
    ["THRESHOLD_MISMATCH -> REJECT", task("gk_03", tx(3), { public_balance: "999" }), "REJECT", "THRESHOLD_MISMATCH"],
    ["EXPIRED_CONDITION -> REJECT", task("gk_04", tx(4), { current_block: 19842202 }), "REJECT", "EXPIRED_CONDITION"],
    ["RECIPIENT_MISMATCH -> REJECT", task("gk_05", tx(5), { recipient: ADDR_OTHER }), "REJECT", "RECIPIENT_MISMATCH"],
    ["AMOUNT_OVERFLOW -> REJECT", task("gk_06", tx(6), { amount: "1001" }), "REJECT", "AMOUNT_OVERFLOW"],
  ];
  for (const [name, env, wantDecision, wantCode] of cases) {
    const r = await postTask(env);
    check(`${name} (sig ok: ${r.sigOk})`,
      r.status === 200 && r.json?.decision === wantDecision && r.json?.reason_code === wantCode
        && r.json?.proof_tx === env.input.proof_tx && r.sigOk,
      JSON.stringify(r.json));
  }

  // 11. Boundary values: balance == minimum, amount == max, block == expiry -> APPROVE
  const boundary = await postTask(task("gk_07", tx(7), {
    public_balance: "1000", amount: "1000", current_block: 19842201,
  }));
  check("boundary (balance==min, amount==max, block==expiry) -> APPROVE",
    boundary.json?.decision === "APPROVE" && boundary.json?.reason_code === "VALID_CONDITION",
    JSON.stringify(boundary.json));

  // 12. PROOF_REUSED: tx(1) was already used by gk_01 (approved). New task, same proof_tx.
  const reuse = await postTask(task("gk_08", tx(1)));
  check("PROOF_REUSED (same proof_tx, new task_id) -> REJECT",
    reuse.json?.decision === "REJECT" && reuse.json?.reason_code === "PROOF_REUSED",
    JSON.stringify(reuse.json));

  // 13. Idempotency: resend gk_01 verbatim -> same APPROVE, NOT flagged as reuse.
  const replay = await postTask(task("gk_01", tx(1)));
  check("idempotent replay of gk_01 -> same APPROVE (not PROOF_REUSED)",
    replay.json?.decision === "APPROVE" && replay.json?.reason_code === "VALID_CONDITION",
    JSON.stringify(replay.json));

  // 14. Malformed input fails closed.
  const malformed = await postTask({
    type: "agent-games.proof-gatekeeper.v1", task_id: "gk_09",
    input: { registered_vk: VK_REG }, // missing everything else
  });
  check("malformed input -> REJECT INVALID_TASK",
    malformed.json?.decision === "REJECT" && malformed.json?.reason_code === "INVALID_TASK",
    JSON.stringify(malformed.json));

  // 15. Persistence across restart: tx(3) was seen pre-restart (gk_03).
  await stopServer();
  await startServer();
  const afterRestart = await postTask(task("gk_10", tx(3)));
  check("seen-set survives restart (tx(3) still PROOF_REUSED)",
    afterRestart.json?.decision === "REJECT" && afterRestart.json?.reason_code === "PROOF_REUSED",
    JSON.stringify(afterRestart.json));
  const freshAfterRestart = await postTask(task("gk_11", tx(11)));
  check("fresh proof_tx after restart -> APPROVE",
    freshAfterRestart.json?.decision === "APPROVE",
    JSON.stringify(freshAfterRestart.json));
} finally {
  await stopServer();
}

console.log(`\n${pass} passed, ${fail} failed. state dir: ${STATE_DIR}`);
process.exit(fail ? 1 : 0);
