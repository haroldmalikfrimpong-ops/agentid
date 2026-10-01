# verifier_attestation — 60-mutation negative battery

Independent mutation / negative test against AgentID's published
`verifier_attestation` conformance fixture (`ctef-verifier-attestation/v0.1`).

Pinned here so the result can be cited by path + commit. Run it yourself:

```
cd conformance/verifier-attestation-mutations
node mutation-test.mjs
```

Node 18+ (uses `base64url` and `crypto.verify` with Ed25519; no dependencies).
Expected output is in [`EXPECTED_OUTPUT.txt`](./EXPECTED_OUTPUT.txt):
**4/4 baselines verify, 60/60 mutations rejected, 0 escapes.**

## What it proves (and what it doesn't)

Byte-reproducibility ("byte-identical on a fresh clone") proves a producer and a
consumer *agree* on bytes. It does **not** prove the verifier *rejects* bytes that
don't reconcile. The only way to tell a real verifier from a structural / bounds-only
checker is a negative test: mutate every field and assert each mutation is rejected.
This harness is that test for our vectors.

The verifier in `mutation-test.mjs` is **independent of the generator**. It does not
import the code that produced the fixture. It reconstructs the signing public key from
the fixture's `dev_signing_pubkey_b58` (base58 -> 32 raw bytes -> SPKI
`302a300506032b6570032100` prefix -> Ed25519 `KeyObject`) and re-derives everything
it checks.

## The 6 checks — ALL required for ACCEPT

1. JWS EdDSA signature valid over `header.body` against the reconstructed pubkey
2. `header.kid` == `verifier.kid` (signing key bound to the claimed issuer)
3. `JCS(core)` == base64url-decode(jws body) (published object == the signed body)
4. published `digest` == `sha256(JCS(core))` (digest checked, not assumed)
5. `binding_digest` == `sha256(JCS({amount_usd, charge_ref, nonce, subject_did}))`, recomputed
6. `admission.verdict` + `reason_code` re-derived from policy inputs
   (`permitted`, `amount_usd` vs `dynamic_limit_usd`, dual-approval threshold 500)
   match the published values

`core` = the published object minus `digest` and `jws`. JCS is RFC 8785.

## The battery — 60 mutations (15 per vector x 4 vectors)

Per vector, 14 field mutations plus 1 forged-issuer re-sign:

- `digest` -> garbage
- `binding_digest` -> garbage (bound fields untouched)
- bound-field change alone: `amount_usd` +1e6 / `charge_ref` / `nonce` / `subject.did`
- bound-field change **and** `binding_digest` honestly recomputed, no re-sign
- `verdict` -> `admit`; `permitted` -> `true`; `dynamic_limit_usd` inflated; `trust_level` +1
- `action_ref` -> garbage
- `fast_gates.identity` spoofed
- `expires_at` extended
- JWS signature bit-flip
- **forged issuer**: escalated core (deny -> admit, limit inflated), `binding_digest` and
  `digest` recomputed honestly, signed with a *different* Ed25519 key, `kid` spoofed to
  the real verifier's kid

Every one must be rejected. The untampered vector must verify (baseline).

## Vectors

`verifier_attestation_fixture.json` is a verbatim copy of the dev-key fixture the
harness was built against. Its four scenarios (`admit_L3_payment_50`,
`deny_L1_payment_scope`, `deny_L3_limit_exceeded`, `flag_L3_dual_approval`) are
byte-identical to `conformance_scenarios` in `tests/verifier_attestation_fixture.json`
at the repo root; only the top-level wrapper keys differ. The vectors are signed with a
**local dev key**; the pubkey in the file is the public half and is safe to publish.
Production attestations are signed with the key published at
`https://getagentid.dev/.well-known/jwks.json`.

## Gotcha: the no-op guard

The first run of this battery reported "4 escapes". All four were **no-op mutations**:
setting a field to the value it already held (e.g. `permitted -> true` on a vector that
was already permitted). Those were test flaws, not verifier gaps.

The harness now skips any mutation where
`JSON.stringify(mutated) === JSON.stringify(original)`. Without that guard a mutation
battery under-reports its own catch-rate. If you port this test, keep the guard.

## Honest limit: `action_ref` is not self-recomputable

`action_ref` is integrity-protected by the signature (mutating it is caught, check 1/3),
but its **preimage is not self-recomputable from the envelope alone**: `action_type` is
not carried as a field. It is verifiable only by a counterparty that holds the same
action tuple out of band. That is the name-vs-digest / join-key property, and it is
deliberate, but it means check 5 covers `binding_digest`, not `action_ref`. This
harness does not claim otherwise.
