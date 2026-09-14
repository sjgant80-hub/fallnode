# FallNode

**LIVE: https://sjgant80-hub.github.io/fallnode/**

The sovereign runtime — layer 3 of the sovereign-node factory. Run your
[minted](https://github.com/sjgant80-hub/fallforge-mint) SLM on **your own metal**, behind real
capability grants. Own once, not rent. Data never leaves.

- **The trust chain, enforced at boot** — the server verifies the mint manifest's hash and
  Ed25519 signature before serving. No verified manifest, no serving.
- **Access is a capability, not a password** — the owner's key signs grant tokens (holder,
  scope, budget over kernel-pinned bytes). Scope and budget enforced server-side; a forged
  token dies on the signature; **a refusal charges 0**.
- **The limb is a rule, not a vibe** — a deterministic format failure (required JSON fields
  missing) may escalate to a bigger model, **labelled** `escalated: true, by: <limb>` at limb
  price. The small model is the default; the big one is a tool it borrows.
- **Everything lands on a hash-chained service ledger** — serve, ask, refusal, escalation —
  verifiable by anyone (the live page re-verifies the shipped session in your browser).

## The shipped session (real, captured)

`triage-1b` served with `qwen2.5:7b` as limb, one holder, an 8-unit token:

1. A triage ask → the node answers in format — charged 1
2. A "forget the form" attack → the node **holds** format — charged 1
3. A forged token (budget 9999) → **refused on the signature — charged 0**
4. A YAML+French attack breaks the node's format → **the limb answers, labelled** — charged 6
5. Budget exhausted → **refused — charged 0**

8 of 8 units spent, 6 ledger links, chain valid.

## Run it

```bash
node --test kernel.test.mjs
node tools/witness.mjs mutate kernel.mjs --timeout 20000 --cap 500 --test node --test kernel.test.mjs
node server.mjs --manifest ../fallforge-mint/out/manifest.json --port 8788 \
  --limb qwen2.5:7b --format json:category,urgency,order
node grant.mjs --node triage-1b --holder ada --scope ask,limb --budget 8
curl -X POST http://127.0.0.1:8788/ask -H 'content-type: application/json' \
  -d '{"token": <token>, "message": "double-charged on order 5512, please refund"}'
```

## Honest limits (v1)

The server binds **127.0.0.1 only, by design** — exposing it is your decision and your firewall.
Charges are internal capability units, **not money** (the money rail waits for legal counsel).
A token proves the owner's key issued it, not who holds it — treat a token like cash. Escalation
catches "failed to answer in shape", not "subtly wrong" — a wrong-but-well-formed answer stands
(quality is the gate's job at mint time; the runtime enforces shape, budget and provenance).
Kernel mutation-witnessed in CI (61/64, three argued equivalents); the shipped ledger re-verified
against the shipped kernel on every push. MIT.
