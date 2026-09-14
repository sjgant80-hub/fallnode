import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHARGE_ASK, CHARGE_LIMB, MAX_ASK_CHARS, sha256, canon,
  makeGrant, attenuate, charge, grantSignable,
  validAsk, shouldEscalate, appendLedger, verifyLedger,
} from './kernel.mjs';

test('sha256 + canon: FIPS-pinned, order-blind, primitive-distinct', () => {
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('').hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256(0).ok, false);
  assert.equal(canon({ b: 1, a: 2 }), canon({ a: 2, b: 1 }));
  assert.notEqual(canon({ x: 5 }), canon({ x: '5' }));
  assert.notEqual(canon({ x: null }), canon({ x: 0 }));
  assert.notEqual(canon({ x: true }), canon({ x: false }));
});

test('constants pinned numerically', () => {
  assert.equal(CHARGE_ASK, 1);
  assert.equal(CHARGE_LIMB, 5);
  assert.equal(MAX_ASK_CHARS, 8000);
});

// ── grants
test('makeGrant + attenuate: a child never exceeds its parent — boundaries exact', () => {
  const root = makeGrant('owner', ['ask', 'limb'], 100).grant;
  assert.equal(attenuate(root, 'a', ['ask'], 100).ok, true);            // exactly what remains
  assert.equal(attenuate(root, 'b', ['ask'], 101).ok, false);           // one over
  assert.equal(attenuate(root, 'c', ['ask', 'admin'], 10).ok, false);   // scope parent lacks
  const spent = { holder: 'o', scope: ['ask'], budget: 100, spent: 60 };
  assert.equal(attenuate(spent, 'd', ['ask'], 40).ok, true);            // exactly the remainder
  assert.equal(attenuate(spent, 'e', ['ask'], 41).ok, false);
  assert.equal(makeGrant('n', [], 0).ok, true);                         // zero budget is a valid grant
  assert.equal(makeGrant('', ['a'], 5).ok, false);                      // empty holder
  assert.equal(makeGrant(7, ['a'], 5).ok, false);                       // non-string holder
  assert.equal(makeGrant('n', 'a', 5).ok, false);
  assert.equal(makeGrant('n', ['a', ''], 5).ok, false);
  assert.equal(makeGrant('n', ['a', 7], 5).ok, false);
  assert.equal(makeGrant('n', [], -1).ok, false);
  assert.equal(makeGrant('n', [], 1.5).ok, false);
});

test('charge: budget boundary exact, refusal charges NOTHING, grant object never mutates', () => {
  const g = makeGrant('n', ['ask'], 10).grant;
  const at = charge(g, 'ask', 10);
  assert.equal(at.allowed, true);                       // exactly the budget
  assert.equal(at.grant.spent, 10);
  assert.equal(charge(at.grant, 'ask', 1).allowed, false);   // one over
  assert.equal(charge(g, 'launch', 1).allowed, false);
  assert.equal(charge(g, 'launch', 1).charged, 0);
  assert.equal(charge(g, '', 1).allowed, false);
  assert.equal(charge(g, 7, 1).allowed, false);
  assert.equal(charge(g, 'ask', -1).allowed, false);
  assert.equal(charge(g, 'ask', 1.5).allowed, false);
  assert.equal(charge(g, 'ask', 0).allowed, true);      // zero cost is a valid charge
  assert.equal(g.spent, 0);                             // the original grant is untouched
  assert.equal(charge({ holder: 'x', scope: ['a'], budget: 5, spent: 9 }, 'a', 0).ok, false);
  assert.equal(charge({ holder: 'x', scope: ['a'], budget: 5, spent: -1 }, 'a', 0).ok, false);
  assert.equal(charge({ holder: 'x', scope: ['a'], budget: 5, spent: 1.5 }, 'a', 0).ok, false);
  assert.equal(charge(null, 'a', 0).ok, false);
  const full = { holder: 'x', scope: ['a'], budget: 5, spent: 5 };
  assert.equal(charge(full, 'a', 0).allowed, true);     // spent === budget is a VALID grant
});

test('kill: charge refusals name their TRUE reason', () => {
  const g = makeGrant('n', ['ask'], 10).grant;
  assert.match(charge(g, 7, 1).why, /unknown action/);
  assert.match(charge(g, '', 1).why, /unknown action/);
  assert.match(charge(g, 'launch', 1).why, /outside the grant/);
  assert.match(charge(g, 'ask', -1).why, /unknown cost/);
  assert.match(charge(g, 'ask', 11).why, /beyond the budget/);
});

test('grantSignable: bound to a node, canonical, spent excluded from the signed body', () => {
  const g = makeGrant('ada', ['ask'], 50).grant;
  const s = grantSignable(g, 'triage-1b');
  assert.equal(s.ok, true);
  assert.equal(s.payload.includes('"spent"'), false);          // spent is server state, not token state
  assert.equal(s.payload.includes('triage-1b'), true);
  assert.equal(grantSignable(g, 'triage-1b').payload, s.payload);
  assert.notEqual(grantSignable(g, 'other-node').payload, s.payload);
  assert.equal(grantSignable(g, '').ok, false);
  assert.equal(grantSignable({ holder: 'x', scope: ['a'], budget: 5, spent: 9 }, 'n').ok, false);
  assert.equal(grantSignable(null, 'n').ok, false);
});

// ── asks and escalation
test('validAsk: bounds exact', () => {
  assert.equal(validAsk({ message: 'hi' }).ok, true);
  assert.equal(validAsk({ message: 'x'.repeat(MAX_ASK_CHARS) }).ok, true);
  assert.equal(validAsk({ message: 'x'.repeat(MAX_ASK_CHARS + 1) }).ok, false);
  assert.equal(validAsk({ message: '   ' }).ok, false);
  assert.equal(validAsk({ message: 7 }).ok, false);
  assert.equal(validAsk(null).ok, false);
});

test('shouldEscalate: deterministic — a held format stands, every failure mode escalates', () => {
  const F = { type: 'json', required: ['category', 'urgency'] };
  const E = (out) => shouldEscalate(out, F);
  assert.equal(E('{"category":"refund","urgency":"high"}').escalate, false);
  assert.equal(E('Sure! {"category":"refund","urgency":"low","extra":1} done').escalate, false);   // wrapped is fine
  assert.equal(E('{"category":"refund"}').escalate, true);              // missing required field
  assert.match(E('{"category":"refund"}').why, /urgency/);              // names the missing field
  assert.equal(E('no json here').escalate, true);
  assert.equal(E('{"category": "refund"').escalate, true);              // unbalanced
  assert.equal(E('{bad json}').escalate, true);
  assert.equal(E(12).escalate, true);                                   // no output
  assert.equal(E('[1,2]').escalate, true);                              // no object
  assert.equal(shouldEscalate('anything at all', { type: 'any' }).escalate, false);
  assert.equal(shouldEscalate('x', { type: 'vibes' }).ok, false);       // unknown format refuses
  assert.equal(shouldEscalate('x', { type: 'json' }).ok, false);        // json without required refuses
  assert.equal(shouldEscalate('x', { type: 'json', required: ['a', ''] }).ok, false);
  assert.equal(shouldEscalate('x', { type: 'json', required: ['a', 7] }).ok, false);
  assert.equal(shouldEscalate('x', null).ok, false);
});

// ── the service ledger
test('ledger: clean chain verifies; genesis pinned; every action recorded in order', () => {
  let c = appendLedger([], { act: 'serve', node: 'triage-1b' }).chain;
  c = appendLedger(c, { act: 'ask', by: 'ada', charged: 1 }).chain;
  c = appendLedger(c, { act: 'refused', by: 'ada', charged: 0, why: 'beyond the budget' }).chain;
  c = appendLedger(c, { act: 'limb', by: 'ada', charged: 5 }).chain;
  assert.equal(c[0].prevHash, 'GENESIS');
  const v = verifyLedger(c);
  assert.equal(v.valid, true);
  assert.equal(v.length, 4);
  assert.equal(verifyLedger([]).valid, true);
  assert.equal(appendLedger('x', {}).ok, false);
  assert.equal(appendLedger([], 'x').ok, false);
});

test('ledger: TAMPER anywhere breaks at the right link; forgeries are refused', () => {
  let c = appendLedger([], { act: 'one' }).chain;
  c = appendLedger(c, { act: 'two' }).chain;
  c = appendLedger(c, { act: 'three' }).chain;
  const tampered = c.map((x, i) => i === 1 ? { ...x, entry: { act: 'TWO-FORGED' } } : x);
  assert.equal(verifyLedger(tampered).valid, false);
  assert.equal(verifyLedger(tampered).brokenAt, 1);
  assert.equal(verifyLedger([c[0], c[2], c[1]]).valid, false);          // reorder
  assert.equal(verifyLedger([null]).valid, false);
  assert.equal(verifyLedger('x').ok, false);
  // a STRING entry with an honestly-computed hash: only the type guard stands in the way
  const forgedHash = sha256('GENESIS|' + '"x"').hash;
  assert.equal(verifyLedger([{ seq: 0, prevHash: 'GENESIS', hash: forgedHash, entry: 'x' }]).valid, false);
  // an ARRAY link with honest fields and a correctly-computed hash
  const arr = []; arr.seq = 0; arr.prevHash = 'GENESIS'; arr.hash = sha256('GENESIS|{}').hash; arr.entry = {};
  assert.equal(verifyLedger([arr]).valid, false);
});

test('kill: canon distinguishes primitives through the ledger hash', () => {
  const h = (entry) => appendLedger([], entry).chain[0].hash;
  assert.notEqual(h({ x: 5 }), h({ x: 6 }));
  assert.notEqual(h({ x: true }), h({ x: false }));
  assert.notEqual(h({ x: null }), h({ x: 0 }));
  assert.equal(appendLedger([], { x: null }).ok, true);
});
