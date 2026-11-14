// zkVerify Agent Games — Proof Gatekeeper agent (DECISION-ONLY).
// Plain Node.js (node:http + node:crypto), no dependencies.
// Spec: ~/workspace/zkverify/NOTES.md (source of truth).
//
// What it does:
//   POST /agent  — HMAC-verified task/preflight handler
//   GET  /       — health check  {"ok": true}
//   GET  /health — health check  {"ok": true}
//
// Decision logic (deterministic, fail closed — no LLM in the path):
//   1. proof_vk == registered_vk            else REJECT VK_SUBSTITUTION
//   2. public_balance >= minimum (BigInt)   else REJECT THRESHOLD_MISMATCH
//   3. proof_tx not in seen-set             else REJECT PROOF_REUSED
//   4. current_block <= expiry_block        else REJECT EXPIRED_CONDITION
//   5. recipient == condition_recipient     else REJECT RECIPIENT_MISMATCH
//   6. amount <= max_transfer (BigInt)      else REJECT AMOUNT_OVERFLOW
//   7. all pass                             -> APPROVE VALID_CONDITION
// First failure decides the reason_code. Any malformed input / error ->
// REJECT with reason_code INVALID_TASK (fail closed).
//
// Groth16 proof generation is NOT implemented here: the circuit input
// mapping is not published (see NOTES.md blocker #1). A correct decision
// without a valid proof still scores +10/task (vs +12+bonus with proof).
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
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const STATE_DIR = process.env.STATE_DIR || path.join(process.cwd(), "state");
const DEV_MODE = !SECRET;

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
// decisions: { task_id: { decision, reason_code, proof_tx } }
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
  // 4. Expiry
  if (typeof current_block !== "number" || typeof expiry_block !== "number"
    || !Number.isFinite(current_block) || !Number.isFinite(expiry_block))
    throw new Error("missing block heights");
  if (current_block > expiry_block)
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
    req.on("end", () => {
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
      out = { ...out, proof_tx: proofTx };

      // Record the proof reference as seen (every proof_tx we process).
      // Assumption (see README): the platform's "already accepted" means
      // "used in a previous task", so a reference seen once must never be
      // approved again, even if its first task was rejected for another
      // trap. Idempotent retries of the same task_id never reach here.
      if (proofTx) seen.add(proofTx.toLowerCase());
      if (taskId) decisions[taskId] = out;
      persist();

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
  console.log(`gatekeeper agent listening on http://${HOST}:${PORT} (state: ${STATE_DIR}, seen: ${seen.size}, decisions: ${Object.keys(decisions).length})`);
});
