# fallcharter · design note

> Spec: **fallcharter-spec-v1**. The contract of the kernel/bylaws governance split.

## Surface

`charter.mjs` exports:

- `sealKernel(invariants)` → `{ invariants, kernelHash }` — freezes invariants under a SHA-256 seal.
- `charter(kernel, bylaws)` → `{ kernel, bylaws, version, parent }`.
- `verifyCharter(c)` → `{ valid, kernelIntact, kernelHash, breaks }`.
- `forkCharter(parent, newBylaws)` → child with the same kernel, new bylaws.
- `amendBylaw(c, id, rule)` → new charter with that bylaw changed.
- `attemptKernelChange(c, id, rule)` → `{ detected, oldHash, newHash }` — proves the barrier.
- `sha256Hex(str)`.

## Invariants

1. **The kernel is sealed by its content.** `kernelHash = SHA-256(canonical invariants)`, canonical =
   sorted by id, so ordering can't change identity. Any invariant edit changes the hash.
2. **Tamper-evident.** `verifyCharter` re-hashes the invariants and rejects a mismatch (`kernelIntact:
   false`).
3. **Forks carry the kernel unchanged.** A fork copies the parent kernel and records `parent =
   parent.kernelHash`; a charter with a broken kernel cannot be forked.
4. **Bylaws are free but bounded.** Amend/add/remove is fine; bylaw ids must be unique and may not
   shadow a kernel invariant id.
5. **Real crypto, zero deps.** Web Crypto SHA-256; no dependencies.

## Verification

`npm test` — deterministic order-independent sealing, malformed-kernel rejection, fresh-charter
verify, invariant-tamper detection, the barrier (attempted kernel change always detected), fork keeps
the kernel, broken-kernel fork rejected, bylaw amendment leaves the kernel intact, shadow + duplicate
bylaw rejection. CI runs it on push.
