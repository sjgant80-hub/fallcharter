#!/usr/bin/env node
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sealKernel, charter, verifyCharter, forkCharter, amendBylaw, attemptKernelChange, sha256Hex } from './charter.mjs';

const INV = [
  { id: 'k1', rule: 'the ledger is append-only' },
  { id: 'k2', rule: 'deletion is local and user-initiated' },
];
const BYLAWS = [{ id: 'b1', rule: 'quorum is 3' }, { id: 'b2', rule: 'proposals last 7 days' }];

async function fresh() { return charter(await sealKernel(INV), BYLAWS); }

test('sealing a kernel is deterministic and order-independent', async () => {
  const a = await sealKernel(INV);
  const b = await sealKernel([...INV].reverse());
  assert.equal(a.kernelHash, b.kernelHash, 'invariant order does not change the seal');
  assert.match(a.kernelHash, /^[0-9a-f]{64}$/);
});

test('sealKernel rejects an empty or malformed kernel', async () => {
  await assert.rejects(() => sealKernel([]), /at least one invariant/);
  await assert.rejects(() => sealKernel([{ id: 'x' }]), /id and a rule/);
});

test('a fresh charter verifies with an intact kernel', async () => {
  const v = await verifyCharter(await fresh());
  assert.equal(v.valid, true);
  assert.equal(v.kernelIntact, true);
});

test('TAMPER: altering a kernel invariant breaks verification', async () => {
  const c = await fresh();
  c.kernel.invariants[0].rule = 'the ledger can be rewritten'; // mutate an invariant
  const v = await verifyCharter(c);
  assert.equal(v.valid, false);
  assert.equal(v.kernelIntact, false);
  assert.ok(v.breaks.some(b => /kernelHash mismatch/.test(b)));
});

test('the barrier: attempting a kernel change is always detected via the hash', async () => {
  const c = await fresh();
  const r = await attemptKernelChange(c, 'k1', 'something else');
  assert.equal(r.detected, true);
  assert.notEqual(r.oldHash, r.newHash);
});

test('FORK: a child carries the SAME kernel with different bylaws', async () => {
  const parent = await fresh();
  const child = await forkCharter(parent, [{ id: 'b1', rule: 'quorum is 5' }]);
  assert.equal(child.kernel.kernelHash, parent.kernel.kernelHash, 'kernel unchanged');
  assert.equal(child.parent, parent.kernel.kernelHash);
  assert.notDeepEqual(child.bylaws, parent.bylaws, 'bylaws diverged');
  assert.equal((await verifyCharter(child)).valid, true);
});

test('a charter with a broken kernel cannot be forked', async () => {
  const c = await fresh();
  c.kernel.invariants[0].rule = 'tampered';
  await assert.rejects(() => forkCharter(c, []), /kernel is broken/);
});

test('amending a bylaw is permitted and leaves the kernel intact', async () => {
  const c = await fresh();
  const c2 = amendBylaw(c, 'b1', 'quorum is 4');
  assert.equal(c2.bylaws.find(b => b.id === 'b1').rule, 'quorum is 4');
  assert.equal(c2.version, c.version + 1);
  assert.equal((await verifyCharter(c2)).kernelIntact, true, 'kernel untouched by a bylaw amendment');
});

test('a bylaw may not shadow a kernel invariant id', async () => {
  const c = charter(await sealKernel(INV), [{ id: 'k1', rule: 'trying to override the kernel' }]);
  const v = await verifyCharter(c);
  assert.equal(v.valid, false);
  assert.ok(v.breaks.some(b => /may not shadow the kernel/.test(b)));
});

test('duplicate bylaw ids are rejected', async () => {
  const c = charter(await sealKernel(INV), [{ id: 'b1', rule: 'a' }, { id: 'b1', rule: 'b' }]);
  const v = await verifyCharter(c);
  assert.ok(v.breaks.some(b => /duplicate bylaw/.test(b)));
});

test('sealKernel rejects duplicate invariant ids', async () => {
  await assert.rejects(() => sealKernel([{ id: 'k1', rule: 'a' }, { id: 'k1', rule: 'b' }]), /duplicate invariant id/);
});

test('a bylaw id that only COERCES to a kernel id is still caught as shadowing', async () => {
  const kernel = await sealKernel([{ id: 1, rule: 'numeric id invariant' }]);
  const c = charter(kernel, [{ id: '1', rule: 'string id trying to shadow' }]);
  const v = await verifyCharter(c);
  assert.equal(v.valid, false);
  assert.ok(v.breaks.some(b => /may not shadow the kernel/.test(b)), 'string "1" must not slip past numeric 1');
});

test('malformed charters (many shapes) return invalid — never throw', async () => {
  const good = await sealKernel([{ id: 'k1', rule: 'r' }]);
  const shapes = [
    { kernel: { invariants: 'not-an-array', kernelHash: 'x' } },
    { kernel: { invariants: [null], kernelHash: 'x' } },
    { kernel: { invariants: [undefined], kernelHash: 'x' } },
    { kernel: { invariants: [{ id: 'a', rule: 'r' }, null], kernelHash: 'x' } },
    JSON.parse('{"kernel":{"invariants":[null],"kernelHash":"x"},"bylaws":[]}'),
    { kernel: good, bylaws: {} },   // non-iterable bylaws
    { kernel: good, bylaws: 5 },
  ];
  for (const s of shapes) {
    const v = await verifyCharter(s);
    assert.equal(v.valid, false, `${JSON.stringify(s).slice(0, 40)} → invalid`);
    assert.equal(typeof v.valid, 'boolean', 'returned, not thrown');
  }
  // and forkCharter must reject a broken kernel gracefully, not propagate a raw throw
  await assert.rejects(() => forkCharter({ kernel: { invariants: [null], kernelHash: 'x' }, version: 1 }, []), /kernel is broken/);
});

test('verifyCharter rejects a hand-built kernel with duplicate invariant ids', async () => {
  const kernel = await sealKernel([{ id: 'k1', rule: 'a' }]);
  kernel.invariants.push({ id: 'k1', rule: 'contradictory rule, same id' });   // smuggled in post-seal
  const v = await verifyCharter(charter(kernel, []));
  assert.equal(v.valid, false);
  assert.ok(v.breaks.some(b => /duplicate invariant id/.test(b)));
});

test('amendBylaw isolates ALL bylaws — mutating a result bylaw cannot reach the input', async () => {
  const c = await fresh();
  const c2 = amendBylaw(c, 'b1', 'quorum is 9');
  c2.bylaws.find(b => b.id === 'b2').rule = 'mutated on the child';   // a NON-amended bylaw
  assert.notEqual(c.bylaws.find(b => b.id === 'b2').rule, 'mutated on the child', 'parent bylaw untouched');
});

test('forking isolates the kernel — mutating the child cannot corrupt the parent', async () => {
  const parent = await fresh();
  const child = await forkCharter(parent, [{ id: 'b9', rule: 'x' }]);
  child.kernel.invariants[0].rule = 'child tampers its own kernel';
  assert.equal((await verifyCharter(parent)).kernelIntact, true, 'parent kernel is untouched by the child mutation');
  assert.notEqual(parent.kernel.invariants[0].rule, child.kernel.invariants[0].rule);
});

// ──────────────────────────────────────────────────────────────────
// Designed tests pinning exact boundaries the witness mutation gate flagged as theatre.
// Each targets one branch/operator so the corresponding mutant FAILS this test.
// ──────────────────────────────────────────────────────────────────

test('attemptKernelChange on an UNKNOWN invariant id detects no change (line 120: i.id === invId)', async () => {
  // With `===`, no invariant matches → nothing is rewritten → the hash is identical → detected:false.
  // A `!==` mutant would rewrite EVERY other invariant and falsely report a change.
  const c = await fresh();
  const r = await attemptKernelChange(c, 'no-such-invariant', 'whatever');
  assert.equal(r.detected, false, 'no matching invariant → hash unchanged → nothing detected');
  assert.equal(r.newHash, r.oldHash);
});

test('amendBylaw reports the amended id, and null when nothing matched (line 110: b.id === bylawId)', async () => {
  const c = await fresh();
  assert.equal(amendBylaw(c, 'b1', 'quorum is 6').amended, 'b1', 'a matching bylaw id is recorded');
  assert.equal(amendBylaw(c, 'no-such-bylaw', 'x').amended, null, 'no match → amended is null, not the id');
});

test('forkCharter increments the version by exactly one (line 104: parent.version + 1)', async () => {
  const parent = await fresh();
  const child = await forkCharter(parent, [{ id: 'z', rule: 'r' }]);
  assert.equal(child.version, parent.version + 1, 'child version is parent + 1, not - 1');
});

test('verifyCharter returns invalid (never throws) for null/undefined/empty/kernel-null (line 59: !c || !c.kernel)', async () => {
  for (const bad of [null, undefined, {}, { kernel: null }]) {
    const v = await verifyCharter(bad);
    assert.equal(v.valid, false, `${JSON.stringify(bad)} → invalid`);
    assert.equal(v.kernelIntact, false);
  }
});

test('sealKernel rejects a null invariant with the designed error, not a raw TypeError (line 41: !i || ...)', async () => {
  await assert.rejects(() => sealKernel([null]), /id and a rule/, 'null invariant → designed error');
  await assert.rejects(() => sealKernel([{ rule: 'r' }]), /id and a rule/, 'missing id → designed error');
});

test('a kernel invariant that is an object missing its rule is caught as malformed (line 62: i.id == null || i.rule == null)', async () => {
  const kernel = await sealKernel([{ id: 'k1', rule: 'r' }]);
  kernel.invariants.push({ id: 'k2' });   // an object, has an id, but NO rule
  const v = await verifyCharter(charter(kernel, []));
  assert.equal(v.valid, false);
  assert.ok(v.breaks.some(b => /a kernel invariant is malformed/.test(b)),
    'a missing-rule invariant must be reported as malformed, not merely as a hash mismatch');
});

test('a bylaw missing its rule is flagged, and a null bylaw does not throw (line 85: b == null || b.id == null || b.rule == null)', async () => {
  const kernel = await sealKernel(INV);
  const v1 = await verifyCharter(charter(kernel, [{ id: 'b9' }]));   // object, has id, no rule
  assert.equal(v1.valid, false);
  assert.ok(v1.breaks.some(b => /missing an id or rule/.test(b)), 'missing-rule bylaw is flagged');
  const v2 = await verifyCharter({ kernel, bylaws: [null] });        // a null bylaw must not throw
  assert.equal(v2.valid, false);
  assert.ok(v2.breaks.some(b => /missing an id or rule/.test(b)), 'null bylaw is flagged, not thrown');
});

test('the canonical reseal is order-independent even for duplicate invariant ids (lines 29 & 33: _cmp tie-break)', async () => {
  // Canonical form sorts by (id, rule); with equal ids the rule "a" must precede "b" REGARDLESS of
  // input order. A broken _cmp equal-branch (>=/<=) or a broken || tie-break would let input order
  // change the reseal, making kernelIntact depend on array order rather than on genuine tampering.
  const H = await sha256Hex(JSON.stringify([{ id: 'k1', rule: 'a' }, { id: 'k1', rule: 'b' }]));
  const forward  = { kernel: { invariants: [{ id: 'k1', rule: 'a' }, { id: 'k1', rule: 'b' }], kernelHash: H }, bylaws: [] };
  const backward = { kernel: { invariants: [{ id: 'k1', rule: 'b' }, { id: 'k1', rule: 'a' }], kernelHash: H }, bylaws: [] };
  assert.equal((await verifyCharter(forward)).kernelIntact, true, 'forward order reseals to the canonical hash');
  assert.equal((await verifyCharter(backward)).kernelIntact, true, 'backward order reseals to the SAME canonical hash');
});
