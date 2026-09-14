// FallNode — the sovereign runtime's pure core. Layer 3 of the sovereign-node factory: the law
// under which a minted node is SERVED. Own metal, data never leaves; every ask passes a real
// capability grant (attenuating, budget-bounded — a refusal charges nothing); escalation to a
// bigger limb happens only on a DETERMINISTIC format failure, is labelled, and costs more;
// every ask, refusal and escalation lands on a hash-chained service ledger anyone can verify.
// The runtime refuses to serve a mint whose signed manifest does not verify — that check runs
// at the edge with the vendored mint kernel; THIS kernel owns the serving law.
// No I/O here. Pure and total: garbage in → { ok:false, why }, never a throw.

export const CHARGE_ASK = 1;        // a plain answer by the owned node
export const CHARGE_LIMB = 5;       // an escalated answer by the limb — bigger metal, bigger charge
export const MAX_ASK_CHARS = 8000;  // a request is a message, not an upload

const isStr = (v) => typeof v === 'string';
const isInt = (v) => Number.isInteger(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

// ── SHA-256 + canonical JSON (the estate's proven pair) ─────────────────────────────────────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── the capability lattice: attenuating grants — the wallet's law, serving-side ─────────────────
function validGrant(g) {
  if (!isObj(g)) return 'a grant is { holder, scope, budget, spent }';
  if (!isStr(g.holder) || g.holder.length === 0) return 'grant holder must be a non-empty string';
  if (!Array.isArray(g.scope)) return 'grant scope must be an array of action names';
  for (const s of g.scope) if (!isStr(s) || s.length === 0) return 'each scope entry must be a non-empty string';
  if (!isInt(g.budget) || g.budget < 0) return 'grant budget must be a non-negative integer';
  if (!isInt(g.spent) || g.spent < 0) return 'grant spent must be a non-negative integer';
  if (g.spent > g.budget) return 'grant spent exceeds its budget';
  return null;
}

export function makeGrant(holder, scope, budget) {
  const g = { holder, scope: Array.isArray(scope) ? scope.slice() : scope, budget, spent: 0 };
  const bad = validGrant(g);
  if (bad) return { ok: false, why: bad };
  return { ok: true, grant: g };
}

/** attenuate(parent, holder, scope, budget) — a child gets a subset and what is left, never more. */
export function attenuate(parent, holder, scope, budget) {
  const badP = validGrant(parent);
  if (badP) return { ok: false, why: 'parent: ' + badP };
  const child = makeGrant(holder, scope, budget);
  if (!child.ok) return { ok: false, why: 'child: ' + child.why };
  for (const s of child.grant.scope) {
    if (!parent.scope.includes(s)) return { ok: false, why: 'a child cannot hold scope the parent lacks: ' + s };
  }
  const remaining = parent.budget - parent.spent;
  if (child.grant.budget > remaining) return { ok: false, why: 'a child cannot hold more budget than the parent has left' };
  return { ok: true, grant: child.grant };
}

/** charge(grant, action, cost) — fail-safe: unknown or outside is refused, and a refusal charges 0. */
export function charge(grant, action, cost) {
  const bad = validGrant(grant);
  if (bad) return { ok: false, why: bad };
  if (!isStr(action) || action.length === 0) return { ok: true, allowed: false, charged: 0, grant, why: 'unknown action — refused' };
  if (!isInt(cost) || cost < 0) return { ok: true, allowed: false, charged: 0, grant, why: 'unknown cost — refused' };
  if (!grant.scope.includes(action)) return { ok: true, allowed: false, charged: 0, grant, why: 'outside the grant — refused' };
  if (grant.spent + cost > grant.budget) return { ok: true, allowed: false, charged: 0, grant, why: 'beyond the budget — refused' };
  return { ok: true, allowed: true, charged: cost, grant: { ...grant, scope: grant.scope.slice(), spent: grant.spent + cost }, why: 'within the grant' };
}

/** grantSignable(grant, node) — the EXACT bytes the node owner's key signs to issue a token. */
export function grantSignable(grant, node) {
  const bad = validGrant(grant);
  if (bad) return { ok: false, why: bad };
  if (!isStr(node) || node.length === 0) return { ok: false, why: 'a token is bound to a node name' };
  return { ok: true, payload: canon({ kind: 'fallnode-grant', node, grant: { holder: grant.holder, scope: grant.scope, budget: grant.budget } }) };
}

// ── the ask: bounded, and escalation is a RULE, not a feeling ───────────────────────────────────
export function validAsk(ask) {
  if (!isObj(ask)) return { ok: false, why: 'an ask is an object' };
  if (!isStr(ask.message) || ask.message.trim().length === 0) return { ok: false, why: 'an ask needs a non-empty message' };
  if (ask.message.length > MAX_ASK_CHARS) return { ok: false, why: 'message exceeds ' + MAX_ASK_CHARS + ' characters' };
  return { ok: true };
}

/** shouldEscalate(output, format) — deterministic: the node's answer failed its declared format.
 *  'json' needs a parseable object carrying every required field; 'any' never escalates. */
export function shouldEscalate(output, format) {
  if (!isObj(format) || !isStr(format.type)) return { ok: false, why: 'a format is { type, ... }' };
  if (format.type === 'any') return { ok: true, escalate: false, why: 'free-form — the node answer stands' };
  if (format.type !== 'json') return { ok: false, why: 'unknown format type: ' + format.type };
  if (!Array.isArray(format.required)) return { ok: false, why: 'json format needs a required fields array' };
  for (const f of format.required) if (!isStr(f) || f.length === 0) return { ok: false, why: 'each required field must be a non-empty string' };
  if (!isStr(output)) return { ok: true, escalate: true, why: 'no output produced' };
  const start = output.indexOf('{');
  if (start === -1) return { ok: true, escalate: true, why: 'no JSON object in the answer' };
  let depth = 0, end = -1, inStr = false, escNext = false;
  for (let i = start; i < output.length; i++) {
    const c = output[i];
    if (escNext) { escNext = false; continue; }
    if (c === '\\') { escNext = true; continue; }
    if (c === '"') inStr = !inStr;
    if (inStr) continue;
    if (c === '{') depth++;
    if (c === '}') { depth--; if (depth === 0) { end = i; break; } }
  }
  if (end === -1) return { ok: true, escalate: true, why: 'unbalanced JSON in the answer' };
  let obj;
  try { obj = JSON.parse(output.slice(start, end + 1)); } catch (e) { return { ok: true, escalate: true, why: 'the answer’s JSON does not parse' }; }
  if (!isObj(obj)) return { ok: true, escalate: true, why: 'the answer’s JSON is not an object' };
  for (const f of format.required) {
    if (!(f in obj)) return { ok: true, escalate: true, why: 'answer JSON is missing the field: ' + f };
  }
  return { ok: true, escalate: false, why: 'the node’s answer holds its format' };
}

// ── the service ledger: every ask, refusal and escalation, hash-chained ─────────────────────────
export function appendLedger(chain, entry) {
  if (!Array.isArray(chain)) return { ok: false, why: 'the ledger is an array' };
  if (!isObj(entry)) return { ok: false, why: 'a ledger entry is an object' };
  const prevHash = chain.length === 0 ? 'GENESIS' : chain[chain.length - 1].hash;
  const h = sha256(prevHash + '|' + canon(entry));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, chain: [...chain, { seq: chain.length, prevHash, hash: h.hash, entry }] };
}

export function verifyLedger(chain) {
  if (!Array.isArray(chain)) return { ok: false, why: 'the ledger is an array' };
  for (let i = 0; i < chain.length; i++) {
    const item = chain[i];
    if (!isObj(item) || !isStr(item.hash) || !isStr(item.prevHash) || !isObj(item.entry)) return { ok: true, valid: false, brokenAt: i };
    if (item.seq !== i) return { ok: true, valid: false, brokenAt: i };
    const expectedPrev = i === 0 ? 'GENESIS' : chain[i - 1].hash;
    if (item.prevHash !== expectedPrev) return { ok: true, valid: false, brokenAt: i };
    const h = sha256(item.prevHash + '|' + canon(item.entry));
    if (!h.ok || h.hash !== item.hash) return { ok: true, valid: false, brokenAt: i };
  }
  return { ok: true, valid: true, length: chain.length };
}
