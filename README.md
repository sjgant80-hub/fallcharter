# fallcharter

**Live:** [sjgant80-hub.github.io/fallcharter](https://sjgant80-hub.github.io/fallcharter/)

A governance charter with two parts, deliberately split so the rules can evolve without the
foundation drifting:

- **KERNEL** — the invariants that must never change. Sealed by a SHA-256 of its invariants
  (`kernelHash`). You cannot mutate an invariant and keep the same identity: any change produces a
  different hash, and every verify/fork checks the invariants still hash to the sealed value. The
  kernel is immutable **by construction, not by promise**.
- **BYLAWS** — the forkable rules. Meant to change: amend, add, remove, or fork a whole new charter
  with different bylaws. What a fork may **not** do is alter the kernel — it carries the parent's
  kernel unchanged, and the `kernelHash` proves it.

The GOVERNANCE descent of the fallkard ecosystem.

## Use

```js
import { sealKernel, charter, verifyCharter, forkCharter, amendBylaw } from './charter.mjs';

const kernel = await sealKernel([
  { id: 'k1', rule: 'the ledger is append-only' },
  { id: 'k2', rule: 'deletion is local and user-initiated' },
]);
const c = charter(kernel, [{ id: 'b1', rule: 'quorum is 3' }]);

await verifyCharter(c);                        // { valid, kernelIntact, breaks }
const child = await forkCharter(c, [...]);     // same kernel, new bylaws
amendBylaw(c, 'b1', 'quorum is 5');            // bylaws change; kernel can't
```

## Test

```
npm test
```

Real Web Crypto SHA-256 (browser + Node ≥ 20). Zero dependencies.
