// zkVerify Agent Games — Proof Gatekeeper agent (WITH Groth16 proofs).
// Plain Node.js (node:http + node:crypto) + snarkjs + js-sha3.
// Spec: ~/workspace/zkverify/NOTES.md; circuit mapping (verified locally
// 2026-11-17): ~/workspace/zkverify/circuit/MAPPING.md.
//
// What it does:
//   POST /agent  — HMAC-verified task/preflight handler
//   GET  /       — health check  {"ok": true}
//   GET  /health — health check  {"ok": true}
//
// Decision logic (deterministic, fail closed — no LLM in the path).
// Order = circuit order (first failure wins); the circuit re-checks the
// decision in witness generation and REFUSES a mismatched decision, so
// decide() must mirror the circuit exactly:
//   1. proof_vk == registered_vk            else REJECT VK_SUBSTITUTION
//   2. public_balance >= minimum (BigInt)   else REJECT THRESHOLD_MISMATCH
//   3. proof_tx not in seen-set             else REJECT PROOF_REUSED
//   4. current_block < expiry_block         else REJECT EXPIRED_CONDITION
//      (STRICT: current == expiry is EXPIRED — verified against the
//      circuit 2026-11-17; the old "<=" reading was wrong at the boundary)
//   5. recipient == condition_recipient     else REJECT RECIPIENT_MISMATCH
//   6. amount <= max_transfer (BigInt)      else REJECT AMOUNT_OVERFLOW
//   7. all pass                             -> APPROVE VALID_CONDITION
// First failure decides the reason_code. Any malformed input / error ->
// REJECT with reason_code INVALID_TASK (fail closed).
//
// Proof: for every decision except PROOF_REUSED, a Groth16 proof is
// generated locally with snarkjs (gatekeeper.wasm/zkey in ./circuit) and
// returned as { proof, public_signals } with the decision. Generation
// takes ~1 s on this VM, well inside the 60 s task deadline. If proof
// generation fails, the decision is still returned WITHOUT a proof
// (a visible -2, not a hang/timeout).
// PROOF_REUSED answers carry NO proof (there is nothing to prove).
//
// Kurier (on-chain confirmation): in scored rounds the platform counts a
// proof as verified only when it is CONFIRMED ON-CHAIN (andruu's Round 3:
// 0/8 counted with proofs in the response but no Kurier submission). When
// KURIER_API_KEY is set, the proof is also submitted to Kurier and polled
// until Finalized (bounded budget, default 40 s); the response's proof_tx
// is then the Kurier tx hash, else it echoes the task's proof_tx. On
// budget expiry the task is still answered with proof + public_signals.
// Without a key the agent still answers with a valid in-response proof.
//
// Env:
//   PORT                     default 3000
//   AGENT_GAMES_HMAC_SECRET  32-byte secret from the dashboard (Rotate Secret).
//                            If unset, the server runs in UNSAFE dev mode:
//                            HMAC verification is DISABLED and responses are
//                            unsigned. NEVER register an endpoint while in
//                            dev mode.
//   STATE_DIR                default ./state — persists seen proof_tx values
//                            and task_id -> response (idempotency) across
//                            restarts. A seen-set that resets on restart
//                            would approve a reused proof.
//   KURIER_API_KEY           optional — free key from kurier.xyz; enables
//                            on-chain confirmation (required for scored rounds
//                            to count proofs as verified).
//   KURIER_API_URL           default https://api.kurier.xyz/api/v1
//   KURIER_POLL_BUDGET_MS    default 40000 (bounded inside the 60 s window)
//   GATEKEEPER_VK_HASH       default 0x6b79...77b0 (registered gatekeeper vk)
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import jsSha3 from "js-sha3";

const { keccak_256 } = jsSha3;

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const STATE_DIR = process.env.STATE_DIR || path.join(process.cwd(), "state");
const DEV_MODE = !SECRET;

// ---------------------------------------------------------------- circuit
const DIR = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(DIR, "circuit", "gatekeeper.wasm");
const ZKEY_PATH = path.join(DIR, "circuit", "gatekeeper_final.zkey");
const VK_HASH = process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

// Kurier (optional — on-chain confirmation for scored rounds)
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const KURIER_API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const KURIER_POLL_BUDGET_MS = Number(process.env.KURIER_POLL_BUDGET_MS || 40000);
const KURIER_POLL_INTERVAL_MS = 3000;
// Soft overall deadline per task: stay inside the platform's 60 s window.
const TASK_BUDGET_MS = 55000;

const SEEN_FILE = path.join(STATE_DIR, "seen.json");
const DECISIONS_FILE = path.join(STATE_DIR, "decisions.json");

// ---------------------------------------------------------------- state
fs.mkdirSync(STATE_DIR, { recursive: true });

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function saveJsonAtomic(file, data) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, file);
}

// seen-set: array of lowercase proof_tx strings
const seen = new Set(loadJson(SEEN_FILE, []));
// decisions: { task_id: { decision, reason_code, proof_tx, ... } }
const decisions = loadJson(DECISIONS_FILE, {});
const persist = () => {
  saveJsonAtomic(SEEN_FILE, [...seen]);
  saveJsonAtomic(DECISIONS_FILE, decisions);
};

// ---------------------------------------------------------------- HMAC
function hmacHex(secret, body) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

// Accept the platform's signature as raw hex, "sha256=<hex>", or base64.
// The guide does not publish the exact encoding; practice mode will confirm.
function verifySignature(secret, rawBody, header) {
  if (!header) return false;
  let sig = String(header).trim();
  if (sig.toLowerCase().startsWith("sha256=")) sig = sig.slice(7);
  const expectedHex = hmacHex(secret, rawBody);
  const expectedB64 = Buffer.from(expectedHex, "hex").toString("base64");
  for (const candidate of [expectedHex, expectedB64]) {
    const a = Buffer.from(candidate, "utf8");
    const b = Buffer.from(sig, "utf8");
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

// ---------------------------------------------------------------- decision
function decide(input) {
  // Throws on malformed input -> caller fails closed (REJECT INVALID_TASK).
  const {
    registered_vk, proof_vk, minimum, public_balance,
    expiry_block, current_block, recipient, condition_recipient,
    amount, max_transfer, proof_tx,
  } = input;
  if (typeof registered_vk !== "string" || typeof proof_vk !== "string")
    throw new Error("missing vk");
  if (typeof proof_tx !== "string" || !proof_tx)
    throw new Error("missing proof_tx");
  if (typeof recipient !== "string" || typeof condition_recipient !== "string")
    throw new Error("missing recipient");

  // 1. VK match (case-insensitive hex compare)
  if (proof_vk.toLowerCase() !== registered_vk.toLowerCase())
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  // 2. Threshold (decimal strings, BigInt)
  if (BigInt(public_balance) < BigInt(minimum))
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  // 3. Proof reuse (seen-set)
  if (seen.has(proof_tx.toLowerCase()))
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  // 4. Expiry — STRICT: current_block >= expiry_block is expired.
  if (typeof current_block !== "number" || typeof expiry_block !== "number"
    || !Number.isFinite(current_block) || !Number.isFinite(expiry_block))
    throw new Error("missing block heights");
  if (current_block >= expiry_block)
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  // 5. Recipient (case-insensitive address compare)
  if (recipient.toLowerCase() !== condition_recipient.toLowerCase())
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  // 6. Amount cap (decimal strings, BigInt)
  if (BigInt(amount) > BigInt(max_transfer))
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  // 7. All pass
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

// ---------------------------------------------------------------- Groth16
function toField(x) {
  const b = typeof x === "bigint" ? x : BigInt(x);
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}
function keccakTaskId(taskId) {
  return toField(BigInt("0x" + keccak_256(Buffer.from(String(taskId), "utf8")))).toString();
}

// Circuit inputs (13) — order/names verified locally 2026-11-17, see
// ~/workspace/zkverify/circuit/MAPPING.md. salt is private (never a
// public signal); decision 1 = APPROVE, 0 = REJECT.
function buildCircuitInput(input, taskId, decision) {
  return {
    registeredVkHash: String(input.registered_vk),
    proofVkHash: String(input.proof_vk),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: String(input.recipient),
    conditionRecipient: String(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: keccakTaskId(taskId),
    salt: "0x" + crypto.randomBytes(32).toString("hex"),
  };
}

async function proveDecision(input, taskId, decision) {
  const circuitInput = buildCircuitInput(input, taskId, decision);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, WASM_PATH, ZKEY_PATH
  );
  console.log(`[prove] task=${taskId} decision=${decision} ${Date.now() - t0}ms`);
  return { proof, publicSignals };
}

// ---------------------------------------------------------------- Kurier
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Submit proof to Kurier and poll until Finalized, bounded by budgetMs.
// Never throws: any failure returns null (or a non-final outcome) and the
// caller still answers the task with the proof + public_signals.
async function submitProofAndPoll(proof, publicSignals, budgetMs) {
  if (!KURIER_API_KEY) return null;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${KURIER_API_URL}/submit-proof/${KURIER_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: VK_HASH },
      }),
    });
    if (!submitRes.ok) {
      console.error(`[kurier] submit-proof HTTP ${submitRes.status}`);
      return null;
    }
    const job = await submitRes.json();
    if (!job.jobId) {
      console.error("[kurier] submit-proof response missing jobId");
      return null;
    }
    console.log(`[kurier] job ${job.jobId} submitted`);
    let status = "Submitted";
    let lastTxHash;
    while (Date.now() < deadline) {
      await sleep(Math.min(KURIER_POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
      let s;
      try {
        const statusRes = await fetch(`${KURIER_API_URL}/job-status/${KURIER_API_KEY}/${job.jobId}`);
        if (!statusRes.ok) { console.error(`[kurier] job-status HTTP ${statusRes.status}`); continue; }
        s = await statusRes.json();
      } catch (e) {
        console.error("[kurier] job-status error:", e.message);
        continue;
      }
      status = s.status ?? status;
      const txHash = s.txHash ?? s.transactionInfo?.txHash;
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") {
        console.error(`[kurier] job ${job.jobId} FAILED`);
        return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
      }
      if (status === "Finalized") {
        console.log(`[kurier] job ${job.jobId} FINALIZED tx=${lastTxHash ?? "n/a"}`);
        return { jobId: job.jobId, status, txHash: lastTxHash, finalized: true };
      }
    }
    console.log(`[kurier] job ${job.jobId} not finalized within budget (last=${status})`);
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (err) {
    console.error("[kurier] submission error:", err.message);
    return null;
  }
}

// ---------------------------------------------------------------- http
function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  if (!DEV_MODE) {
    res.setHeader("x-agent-games-signature", hmacHex(SECRET, body));
  }
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
    return sendSigned(res, 200, { ok: true });
  }

  if (req.method === "POST" && (url.pathname === "/agent" || url.pathname === "/")) {
    const chunks = [];
    let tooBig = false;
    req.on("data", (c) => {
      if (chunks.reduce((n, x) => n + x.length, 0) + c.length > 1_000_000) tooBig = true;
      else chunks.push(c);
    });
    req.on("end", async () => {
      const startedAt = Date.now();
      if (tooBig) return sendSigned(res, 413, { error: "body too large" });
      const raw = Buffer.concat(chunks);

      // HMAC over the RAW body, BEFORE parsing JSON.
      if (!DEV_MODE && !verifySignature(SECRET, raw, req.headers["x-agent-games-signature"])) {
        return sendSigned(res, 401, { error: "bad signature" });
      }

      let body;
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        return sendSigned(res, 400, { error: "invalid JSON" });
      }

      // Preflight handshake.
      if (body && body.type === "agent-games.preflight.v1") {
        return sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      }

      if (!body || body.type !== "agent-games.proof-gatekeeper.v1") {
        return sendSigned(res, 400, { error: "unknown type" });
      }

      const taskId = typeof body.task_id === "string" ? body.task_id : null;
      const proofTx = body.input && typeof body.input.proof_tx === "string"
        ? body.input.proof_tx : null;

      // Idempotency: same task_id -> same response (platform may retry).
      if (taskId && Object.prototype.hasOwnProperty.call(decisions, taskId)) {
        return sendSigned(res, 200, decisions[taskId]);
      }

      let out;
      try {
        if (!body.input || typeof body.input !== "object") throw new Error("missing input");
        out = decide(body.input);
      } catch (e) {
        // Fail closed: any malformed input / uncertainty -> REJECT.
        out = { decision: "REJECT", reason_code: "INVALID_TASK" };
      }

      // Groth16 proof for every decision except PROOF_REUSED (no proof to
      // submit there) and INVALID_TASK (malformed input, nothing to prove).
      let kurierInfo = "skipped";
      if (out.reason_code !== "PROOF_REUSED" && out.reason_code !== "INVALID_TASK" && taskId) {
        try {
          const { proof, publicSignals } = await proveDecision(body.input, taskId, out.decision);
          out.proof = proof;
          out.public_signals = publicSignals;
          // Kurier: on-chain confirmation, bounded so the answer stays
          // inside the 60 s platform window.
          const remaining = TASK_BUDGET_MS - (Date.now() - startedAt);
          const budget = Math.max(0, Math.min(KURIER_POLL_BUDGET_MS, remaining));
          const kurier = await submitProofAndPoll(proof, publicSignals, budget);
          if (kurier) {
            kurierInfo = kurier.finalized ? `finalized tx=${kurier.txHash ?? "n/a"}` : `not-final (${kurier.status})`;
            // The platform confirms the proof_tx on-chain: report the
            // Kurier tx hash when we have one, else echo the task's ref.
            if (kurier.txHash) out.proof_tx = kurier.txHash;
          } else if (KURIER_API_KEY) {
            kurierInfo = "submit-failed";
          }
        } catch (e) {
          // Proof failed (e.g. witness refusal on a decision/circuit
          // mismatch): still answer the decision, without a proof.
          console.error(`[agent] proof generation failed for ${taskId}:`, e.message);
        }
      }
      if (!("proof_tx" in out)) out.proof_tx = proofTx;

      // Record the proof reference as seen (every proof_tx we process).
      // Assumption (see README): the platform's "already accepted" means
      // "used in a previous task", so a reference seen once must never be
      // approved again, even if its first task was rejected for another
      // trap. Idempotent retries of the same task_id never reach here.
      if (proofTx) seen.add(proofTx.toLowerCase());
      if (taskId) decisions[taskId] = out;
      persist();

      console.log(`[task] id=${taskId} decision=${out.decision} reason=${out.reason_code} ` +
        `kurier=${kurierInfo} proof=${out.proof ? "yes" : "no"} proof_tx=${out.proof_tx ?? "none"} ` +
        `${Date.now() - startedAt}ms`);
      return sendSigned(res, 200, out);
    });
    return;
  }

  return sendSigned(res, 404, { error: "not found" });
});

server.listen(PORT, HOST, () => {
  if (DEV_MODE) {
    console.warn("[WARN] AGENT_GAMES_HMAC_SECRET not set — UNSAFE dev mode: HMAC verification DISABLED, responses unsigned. Do NOT register this endpoint.");
  } else {
    console.log("HMAC verification enabled.");
  }
  console.log(`gatekeeper agent listening on http://${HOST}:${PORT} (state: ${STATE_DIR}, seen: ${seen.size}, decisions: ${Object.keys(decisions).length}, kurier: ${KURIER_API_KEY ? "enabled" : "disabled — proofs in-response only"})`);
});
