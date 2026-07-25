# CLAUDE.md · fallcharter

Instructions for any agent working in this repository. See `SPEC.md` for the contract. The GOVERNANCE
descent of the fallkard ecosystem.

## Invariants to preserve — these are the whole point

1. **The kernel is immutable by construction.** `kernelHash` is a SHA-256 of the canonical invariants.
   There must be NO API that edits an invariant while keeping the same hash. `verifyCharter` must
   re-hash and reject any mismatch. If you add a "kernel edit" path, you have destroyed the guarantee.
2. **Canonical = sorted by id.** Ordering must never change the seal. Keep `canonInvariants` sorting.
3. **Forks keep the kernel.** `forkCharter` copies the parent kernel verbatim and records `parent =
   parent.kernelHash`. A broken-kernel charter cannot be forked.
4. **Bylaws are the ONLY mutable surface** — and they may not shadow a kernel invariant id, nor
   duplicate each other. Amendments bump `version`.
5. **Real Web Crypto SHA-256, zero deps.** A change that reddens `npm test` — especially the tamper /
   barrier / fork tests — does not ship.

## Run
```
npm test
```
CI runs `npm test` on every push.

## Seam

Public, general-purpose governance primitive. Kernel / bylaws / invariant / fork / seal language only.
Do NOT introduce the private cosmology (no κ/θ/Ψ, no element or dyad references, no "the Thirteen").
