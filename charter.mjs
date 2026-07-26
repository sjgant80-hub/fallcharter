// ════════════════════════════════════════════════════════════════
// fallcharter · a governance kernel you cannot silently change (the GOVERNANCE descent)
//
// A charter has two parts, deliberately split:
//   • the KERNEL — the invariants that must never change. It is SEALED by a content-hash of its
//     invariants (`kernelHash`). You cannot mutate an invariant and keep the same identity: any change
//     produces a different hash, and every verify/fork checks the invariants still hash to the sealed
//     value. This is the barrier — the kernel is immutable by construction, not by promise.
//   • the BYLAWS — the forkable rules. These are meant to change: amend them, add them, remove them,
//     fork a whole new charter with different bylaws. What a fork may NOT do is alter the kernel; a
//     fork carries the parent's kernel unchanged, and the kernelHash proves it.
//
// So governance can evolve (bylaws) without the foundation drifting (kernel). Real Web Crypto SHA-256
// for the seal. Zero dependencies, browser + Node ≥ 20.
// ════════════════════════════════════════════════════════════════

const subtle = globalThis.crypto?.subtle;
if (!subtle) throw new Error('fallcharter: Web Crypto (crypto.subtle) unavailable — needs a browser or Node >= 20');
const ENC = new TextEncoder();

export async function sha256Hex(str) {
  const d = new Uint8Array(await subtle.digest('SHA-256', ENC.encode(String(str))));
  return [...d].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Canonical form of a set of invariants — sorted by (id, rule) using a CODE-UNIT comparison (not
// locale-dependent localeCompare, which can order Unicode-collation-equal ids differently across
// environments), so ordering can never change the hash. ids are stringified for a stable total order.
const _cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
function canonInvariants(invariants) {
  return JSON.stringify([...invariants]
    .map(i => ({ id: String(i.id), rule: String(i.rule) }))
    .sort((a, b) => _cmp(a.id, b.id) || _cmp(a.rule, b.rule)));
}

// Seal a kernel: freeze its invariants under a content-hash. The hash IS the kernel's identity.
export async function sealKernel(invariants = []) {
  if (!Array.isArray(invariants) || invariants.length === 0) throw new Error('a kernel needs at least one invariant');
  const ids = new Set();
  for (const i of invariants) {
    if (!i || i.id == null || i.rule == null) throw new Error('each invariant needs an id and a rule');
    const key = String(i.id);
    if (ids.has(key)) throw new Error(`duplicate invariant id "${key}" — a kernel's invariants must be uniquely identified`);
    ids.add(key);
  }
  const kernelHash = await sha256Hex(canonInvariants(invariants));
  return { invariants: invariants.map(i => ({ id: i.id, rule: i.rule })), kernelHash };
}

// A charter = a sealed kernel + forkable bylaws.
export function charter(kernel, bylaws = []) {
  return { kernel, bylaws: bylaws.map(b => ({ id: b.id, rule: b.rule })), version: 1, parent: null };
}

// Verify: the kernel's invariants still hash to its sealed kernelHash (untampered), bylaws well-formed
// and uniquely-id'd, and no bylaw collides with a kernel invariant id (bylaws can't shadow the kernel).
export async function verifyCharter(c) {
  const breaks = [];
  if (!c || !c.kernel) return { valid: false, kernelIntact: false, breaks: ['no kernel'] };
  if (!Array.isArray(c.kernel.invariants)) return { valid: false, kernelIntact: false, breaks: ['kernel invariants are malformed'] };
  const reseal = await sha256Hex(canonInvariants(c.kernel.invariants));
  const kernelIntact = reseal === c.kernel.kernelHash;
  if (!kernelIntact) breaks.push('kernel invariants have been altered — kernelHash mismatch');

  // ids are compared as strings so a bylaw id "1" cannot slip past a kernel invariant id 1 (or a
  // duplicate bylaw id 1 vs "1") via type coercion.
  const kernelIds = new Set();
  for (const i of c.kernel.invariants) {
    // a hand-built / deserialised kernel could carry duplicate invariant ids; verify must reject that
    // (not only sealKernel), else two contradictory rules share one id and both read as valid.
    const kid = String(i.id);
    if (kernelIds.has(kid)) breaks.push(`kernel has duplicate invariant id "${i.id}"`);
    kernelIds.add(kid);
  }
  const seen = new Set();
  for (const b of (c.bylaws || [])) {
    if (b == null || b.id == null || b.rule == null) { breaks.push('a bylaw is missing an id or rule'); continue; }
    const bid = String(b.id);
    if (seen.has(bid)) breaks.push(`duplicate bylaw id "${b.id}"`);
    if (kernelIds.has(bid)) breaks.push(`bylaw "${b.id}" collides with a kernel invariant — bylaws may not shadow the kernel`);
    seen.add(bid);
  }
  return { valid: breaks.length === 0, kernelIntact, kernelHash: c.kernel.kernelHash, breaks };
}

// Deep copy of a kernel so a child/amended charter can never retroactively corrupt its parent by
// sharing the same kernel object (the kernelHash proves the kernel is UNCHANGED, but the objects must
// also be isolated so a mutation of one doesn't reach through a shared reference to the other).
const cloneKernel = k => ({ invariants: k.invariants.map(i => ({ id: i.id, rule: i.rule })), kernelHash: k.kernelHash });

// Fork a charter: the child carries the SAME kernel (proven by hash), with new bylaws of its choosing.
// A charter whose kernel is already broken cannot be forked.
export async function forkCharter(parent, newBylaws = []) {
  const v = await verifyCharter(parent);
  if (!v.kernelIntact) throw new Error('cannot fork a charter whose kernel is broken');
  return { kernel: cloneKernel(parent.kernel), bylaws: newBylaws.map(b => ({ id: b.id, rule: b.rule })), version: parent.version + 1, parent: parent.kernel.kernelHash };
}

// Amend a bylaw — permitted. Returns a new charter with an isolated kernel copy; the kernel is
// untouched (verify still passes) and mutating the result cannot reach back into the input.
export function amendBylaw(c, bylawId, newRule) {
  const found = c.bylaws.some(b => b.id === bylawId);
  // clone EVERY bylaw (not just the amended one) so mutating a result bylaw cannot reach back into the
  // input via a shared reference — the isolation the docstring promises.
  const bylaws = c.bylaws.map(b => (b.id === bylawId ? { ...b, rule: newRule } : { ...b }));
  return { ...c, kernel: cloneKernel(c.kernel), bylaws, version: c.version + 1, amended: found ? bylawId : null };
}

// The barrier, made explicit: attempting to change an invariant yields a DIFFERENT kernelHash. There
// is no API that mutates the kernel in place and keeps its identity — this proves why.
export async function attemptKernelChange(c, invId, newRule) {
  const mutated = c.kernel.invariants.map(i => (i.id === invId ? { ...i, rule: newRule } : i));
  const newHash = await sha256Hex(canonInvariants(mutated));
  return { detected: newHash !== c.kernel.kernelHash, oldHash: c.kernel.kernelHash, newHash };
}

export default charter;
