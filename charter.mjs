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

// Canonical form of a set of invariants — sorted by id so ordering can't change the hash.
function canonInvariants(invariants) {
  return JSON.stringify([...invariants].map(i => ({ id: i.id, rule: i.rule })).sort((a, b) => String(a.id).localeCompare(String(b.id))));
}

// Seal a kernel: freeze its invariants under a content-hash. The hash IS the kernel's identity.
export async function sealKernel(invariants = []) {
  if (!Array.isArray(invariants) || invariants.length === 0) throw new Error('a kernel needs at least one invariant');
  for (const i of invariants) if (!i || i.id == null || i.rule == null) throw new Error('each invariant needs an id and a rule');
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
  const reseal = await sha256Hex(canonInvariants(c.kernel.invariants));
  const kernelIntact = reseal === c.kernel.kernelHash;
  if (!kernelIntact) breaks.push('kernel invariants have been altered — kernelHash mismatch');

  const kernelIds = new Set(c.kernel.invariants.map(i => i.id));
  const seen = new Set();
  for (const b of (c.bylaws || [])) {
    if (b.id == null || b.rule == null) breaks.push('a bylaw is missing an id or rule');
    if (seen.has(b.id)) breaks.push(`duplicate bylaw id "${b.id}"`);
    if (kernelIds.has(b.id)) breaks.push(`bylaw "${b.id}" collides with a kernel invariant — bylaws may not shadow the kernel`);
    seen.add(b.id);
  }
  return { valid: breaks.length === 0, kernelIntact, kernelHash: c.kernel.kernelHash, breaks };
}

// Fork a charter: the child carries the SAME kernel (proven by hash), with new bylaws of its choosing.
// A charter whose kernel is already broken cannot be forked.
export async function forkCharter(parent, newBylaws = []) {
  const v = await verifyCharter(parent);
  if (!v.kernelIntact) throw new Error('cannot fork a charter whose kernel is broken');
  return { kernel: parent.kernel, bylaws: newBylaws.map(b => ({ id: b.id, rule: b.rule })), version: parent.version + 1, parent: parent.kernel.kernelHash };
}

// Amend a bylaw — permitted. Returns a new charter; the kernel is untouched (verify still passes).
export function amendBylaw(c, bylawId, newRule) {
  const found = c.bylaws.some(b => b.id === bylawId);
  const bylaws = c.bylaws.map(b => (b.id === bylawId ? { ...b, rule: newRule } : b));
  return { ...c, bylaws, version: c.version + 1, amended: found ? bylawId : null };
}

// The barrier, made explicit: attempting to change an invariant yields a DIFFERENT kernelHash. There
// is no API that mutates the kernel in place and keeps its identity — this proves why.
export async function attemptKernelChange(c, invId, newRule) {
  const mutated = c.kernel.invariants.map(i => (i.id === invId ? { ...i, rule: newRule } : i));
  const newHash = await sha256Hex(canonInvariants(mutated));
  return { detected: newHash !== c.kernel.kernelHash, oldHash: c.kernel.kernelHash, newHash };
}

export default charter;
