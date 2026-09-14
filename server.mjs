#!/usr/bin/env node
// server.mjs — the sovereign runtime. LOCAL ONLY (127.0.0.1, by design — this is the whole
// point): serves a MINTED node whose signed manifest verifies, behind capability-token access.
// Every ask is charged against a real grant; a refusal charges 0; a deterministic format
// failure escalates to the limb (labelled, charged more); everything lands on the ledger.
//
//   node server.mjs --manifest ../fallforge-mint/out/manifest.json [--port 8788]
//                   [--limb qwen2.5:7b] [--format json:category,urgency,order]
//
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  CHARGE_ASK, CHARGE_LIMB, charge, grantSignable, validAsk, shouldEscalate,
  appendLedger, verifyLedger, canon, sha256,
} from './kernel.mjs';
import { verifyManifest, signable } from './vendor/mint-kernel.mjs';

const OLLAMA = process.env.OLLAMA_URL || 'http://localhost:11434';
const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
const PORT = parseInt(args.port || '8788', 10);
const LIMB = args.limb || null;
if (!args.manifest) { console.error('usage: node server.mjs --manifest <manifest.json> [--port N] [--limb model] [--format json:f1,f2]'); process.exit(2); }

// ── the trust chain: refuse to serve a mint that does not verify ────────────────────────────────
const manifest = JSON.parse(readFileSync(args.manifest, 'utf8'));
const vm = verifyManifest(manifest);
if (!vm.ok || vm.valid !== true) { console.error('REFUSED: manifest does not verify — ' + (vm.why || '')); process.exit(1); }
if (manifest.signature && manifest.signature.alg === 'Ed25519') {
  const pub = createPublicKey({ key: Buffer.from(manifest.signature.pub, 'hex'), format: 'der', type: 'spki' });
  const ok = edVerify(null, Buffer.from(signable(manifest).payload, 'utf8'), pub, Buffer.from(manifest.signature.sig, 'hex'));
  if (!ok) { console.error('REFUSED: manifest signature fails'); process.exit(1); }
  console.log('manifest signature: VALID (' + manifest.signature.pub.slice(0, 16) + '…)');
} else { console.error('REFUSED: manifest carries no Ed25519 signature'); process.exit(1); }
const NODE = manifest.node;

let FORMAT = { type: 'any' };
if (args.format && args.format.startsWith('json:')) FORMAT = { type: 'json', required: args.format.slice(5).split(',').filter(Boolean) };

// ── owner key (issues grant tokens) + server state ──────────────────────────────────────────────
const keyPath = join(homedir(), '.fallforge', 'ed25519.pem');
if (!existsSync(keyPath)) { console.error('REFUSED: no owner key at ' + keyPath + ' (mint something first)'); process.exit(1); }
const ownerPub = createPublicKey({ key: readFileSync(keyPath, 'utf8') });
const ownerPubHex = ownerPub.export({ type: 'spki', format: 'der' }).toString('hex');

const STATE = join(homedir(), '.fallforge', 'node-' + NODE + '.json');
let state = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : { grants: {}, ledger: [] };
const save = () => writeFileSync(STATE, JSON.stringify(state) + '\n');

function ledger(entry) {
  const r = appendLedger(state.ledger, entry);
  if (r.ok) { state.ledger = r.chain; save(); }
}
if (state.ledger.length === 0) ledger({ act: 'serve', node: NODE, manifestHash: manifest.hash, format: FORMAT, limb: LIMB || 'none' });

// a token = { grant: {holder, scope, budget}, sig } — signed by the owner key over grantSignable
function acceptToken(token) {
  if (!token || typeof token !== 'object' || !token.grant || typeof token.sig !== 'string') return { ok: false, why: 'a token is { grant, sig }' };
  const g = { holder: token.grant.holder, scope: token.grant.scope, budget: token.grant.budget, spent: 0 };
  const s = grantSignable(g, NODE);
  if (!s.ok) return { ok: false, why: s.why };
  let good = false;
  try { good = edVerify(null, Buffer.from(s.payload, 'utf8'), ownerPub, Buffer.from(token.sig, 'hex')); } catch (e) {}
  if (!good) return { ok: false, why: 'token signature does not verify against the owner key' };
  const id = sha256(s.payload).hash.slice(0, 16);
  if (!state.grants[id]) { state.grants[id] = g; save(); }
  return { ok: true, id, grant: state.grants[id] };
}

async function generate(model, prompt) {
  const t0 = Date.now();
  const res = await fetch(OLLAMA + '/api/generate', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model, prompt, stream: true, options: { temperature: 0, num_predict: 300 } }),
  });
  if (!res.ok) throw new Error(model + ' refused: HTTP ' + res.status);
  let out = '', buf = '';
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
      if (!line) continue;
      try { const j = JSON.parse(line); if (j.response) out += j.response; } catch (e) {}
    }
  }
  return { output: out, ms: Date.now() - t0 };
}

const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };

createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return json(res, 200, { ok: true, node: NODE, manifestHash: manifest.hash, signatureValid: true, format: FORMAT, limb: LIMB || null, ledgerLength: state.ledger.length, ownerPub: ownerPubHex.slice(0, 24) + '…' });
    }
    if (req.method === 'GET' && req.url === '/ledger') {
      const v = verifyLedger(state.ledger);
      return json(res, 200, { ok: true, verified: v, chain: state.ledger });
    }
    if (req.method === 'POST' && req.url === '/ask') {
      let body = '';
      for await (const chunk of req) body += chunk;
      let parsed = null;
      try { parsed = JSON.parse(body); } catch (e) {}
      if (!parsed) return json(res, 400, { ok: false, why: 'body must be JSON { token, message }' });
      const tok = acceptToken(parsed.token);
      if (!tok.ok) { ledger({ act: 'refused', why: tok.why, charged: 0 }); return json(res, 403, { ok: false, why: tok.why }); }
      const ask = validAsk({ message: parsed.message });
      if (!ask.ok) { ledger({ act: 'refused', by: tok.grant.holder, why: ask.why, charged: 0 }); return json(res, 400, { ok: false, why: ask.why }); }

      // charge for the node answer first — a refusal here costs the caller nothing
      const c1 = charge(tok.grant, 'ask', CHARGE_ASK);
      if (!c1.ok || !c1.allowed) {
        ledger({ act: 'refused', by: tok.grant.holder, why: c1.why, charged: 0 });
        return json(res, 402, { ok: false, why: c1.why, remaining: tok.grant.budget - tok.grant.spent });
      }
      state.grants[tok.id] = c1.grant; save();
      const nodeAns = await generate(NODE, parsed.message);
      const esc = shouldEscalate(nodeAns.output, FORMAT);
      if (esc.ok && esc.escalate && LIMB) {
        // the node's answer failed its declared format — the limb may answer, at limb price
        const c2 = charge(state.grants[tok.id], 'limb', CHARGE_LIMB);
        if (c2.ok && c2.allowed) {
          state.grants[tok.id] = c2.grant; save();
          const limbAns = await generate(LIMB, parsed.message);
          ledger({ act: 'limb', by: c2.grant.holder, why: esc.why, charged: CHARGE_ASK + CHARGE_LIMB, ms: nodeAns.ms + limbAns.ms });
          return json(res, 200, { ok: true, answer: limbAns.output, by: LIMB, escalated: true, why: esc.why, charged: CHARGE_ASK + CHARGE_LIMB, remaining: c2.grant.budget - c2.grant.spent, ms: nodeAns.ms + limbAns.ms });
        }
        ledger({ act: 'limb-refused', by: tok.grant.holder, why: c2.why, charged: CHARGE_ASK });
        return json(res, 200, { ok: true, answer: nodeAns.output, by: NODE, escalated: false, formatHeld: false, note: 'format failed and the limb was ' + c2.why, charged: CHARGE_ASK, remaining: c1.grant.budget - c1.grant.spent, ms: nodeAns.ms });
      }
      ledger({ act: 'ask', by: c1.grant.holder, charged: CHARGE_ASK, formatHeld: !(esc.ok && esc.escalate), ms: nodeAns.ms });
      return json(res, 200, { ok: true, answer: nodeAns.output, by: NODE, escalated: false, formatHeld: !(esc.ok && esc.escalate), charged: CHARGE_ASK, remaining: c1.grant.budget - c1.grant.spent, ms: nodeAns.ms });
    }
    json(res, 404, { ok: false, why: 'unknown route' });
  } catch (e) { json(res, 500, { ok: false, why: String(e.message || e) }); }
}).listen(PORT, '127.0.0.1', () => {
  console.log('FallNode serving ' + NODE + ' on http://127.0.0.1:' + PORT + ' (LOCAL ONLY, by design)');
  console.log('  format: ' + JSON.stringify(FORMAT) + ' · limb: ' + (LIMB || 'none') + ' · ledger: ' + state.ledger.length + ' entries');
});
