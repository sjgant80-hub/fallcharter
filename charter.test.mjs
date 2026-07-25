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
