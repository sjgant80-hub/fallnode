#!/usr/bin/env node
// grant.mjs — the owner mints a capability token for their node. The token is the grant body
// signed by the owner's Ed25519 key over the kernel-pinned payload; the server enforces scope
// and budget, and a refusal charges nothing.
//
//   node grant.mjs --node triage-1b --holder ada --scope ask,limb --budget 20
//
import { readFileSync, existsSync } from 'node:fs';
import { createPrivateKey, sign as edSign } from 'node:crypto';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { makeGrant, grantSignable } from './kernel.mjs';

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
if (!args.node || !args.holder || !args.scope || !args.budget) {
  console.error('usage: node grant.mjs --node <name> --holder <who> --scope ask[,limb] --budget N');
  process.exit(2);
}
const g = makeGrant(args.holder, args.scope.split(','), parseInt(args.budget, 10));
if (!g.ok) { console.error('grant refused: ' + g.why); process.exit(1); }
const s = grantSignable(g.grant, args.node);
if (!s.ok) { console.error('refused: ' + s.why); process.exit(1); }
const keyPath = join(homedir(), '.fallforge', 'ed25519.pem');
if (!existsSync(keyPath)) { console.error('no owner key at ' + keyPath); process.exit(1); }
const priv = createPrivateKey(readFileSync(keyPath, 'utf8'));
const sig = edSign(null, Buffer.from(s.payload, 'utf8'), priv).toString('hex');
const token = { grant: { holder: g.grant.holder, scope: g.grant.scope, budget: g.grant.budget }, sig };
console.log(JSON.stringify(token));
