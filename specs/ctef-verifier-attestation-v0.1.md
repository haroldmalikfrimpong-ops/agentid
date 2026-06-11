# CTEF Verifier Attestation — v0.1

**Spec ID:** `ctef-verifier-attestation/v0.1`
**Author:** AgentID (@haroldmalikfrimpong-ops)
**Status:** Draft for A2A#1786 CTEF v0.4 trust-gated-payment design thread
**Aligns with:** CTEF v0.3.2 (attestation layer), A2A#1628 `trust.signals[]`

## 1. Problem

The v0.4 design thread on A2A#1786 opens a **trust-gated-payment boundary**: a payment
gateway enforces token validity + static spend caps + settlement server-side, and—optionally—
consults an **external verifier** immediately before an irreversible mint/charge.

The seam, as converged in-thread (evidai/LemonCake, Agent OS, AgentGraph):

- **Gateway** owns: token validity, static caps (per-mint / daily / monthly), settlement record.
- **External verifier** owns: a fresh, signed *admission decision + dynamic limit* for the subject agent.
- The verifier's output is an **optional `verifier_attestation` field** the gateway checks before charging.
- It must be **bound into settlement, not out-of-band** — the attestation references the exact charge.
- Absence of the field ⇒ the gateway runs **un-gated** (backward compatible).

This spec defines the `verifier_attestation` object: the artifact the verifier emits and the
gateway drops into its pre-mint check.

## 2. Object

```jsonc
{
  "type": "VerifierAttestation",
  "spec": "ctef-verifier-attestation/v0.1",
  "verifier": {
    "id": "did:web:getagentid.dev",
    "name": "AgentID",
    "jwks_url": "https://getagentid.dev/.well-known/jwks.json",
    "kid": "agentid-2026-03",
    "key_source": "jwks_resolved"   // key provenance (#1829): consumer resolves via JWKS
  },
  "subject": { "did": "did:web:...", "agent_id": "..." },

  "admission": {
    "verdict": "admit",              // admit | deny | flag
    "trust_level": 3,                // L1–L4 (integer 1–4)
    "trust_level_label": "L3 — Secured",
    "dynamic_limit_usd": 10000,      // min(trust default, owner-set custom) — the verifier's dynamic cap
    "permitted": true,               // action in the level's permission set
    "reason_code": null              // null on admit; see §4 on deny/flag
  },

  "fast_gates": {                    // gates that can change between original verdict and mint
    "identity": "confirmed",         // confirmed | changed | unresolvable
    "certificate": "valid",          // valid | expired
    "key_lifecycle": "active"        // active | revoked | compromised
  },

  "binding": {                       // binds THIS attestation to THIS settlement — not replayable
    "charge_ref": "<gateway charge_ref>",
    "amount_usd": 50,
    "action_class": "irreversible",  // irreversible | compensable | reversible
    "binding_digest": "<sha256(JCS({amount_usd, charge_ref, nonce, subject_did}))>",
    "nonce": "<uuid>",               // normative replay field (semantics to consumer)
    "action_ref": "<sha256(agent_id‖action_type‖scope‖timestamp_ms)>",
    "action_ref_method": "argentum-core action-ref-v1"  // names the preimage (#1850)
  },
  "attestation_ref": "<sha256(JCS({kid, subject_did, verifier}))>",  // L1 reference (#1920)

  "enforcement": {
    "guarantee": "point_in_time",
    "checked_at": "2026-06-05T...Z",
    "valid_for_seconds": 30,         // tight pre-mint TTL, scaled by action_class
    "compose": "Gateway enforces static caps + settlement; this attestation supplies admission + dynamic limit. Effective limit = min(gateway_static_cap, admission.dynamic_limit_usd). Absent field ⇒ un-gated."
  },

  "issued_at": "2026-06-05T...Z",
  "expires_at": "2026-06-05T...Z",
  "canonicalization": "JCS-RFC-8785",

  "digest": "<sha256(JCS(object without digest/jws))>",
  "jws": "<EdDSA compact JWS over the object without digest/jws>"
}
```

## 3. Gateway integration (pre-mint)

```
1. Gateway receives mint/charge request with optional `verifier_attestation`.
2. If absent  → proceed un-gated (static caps only).      [backward compatible]
3. If present →
   a. Verify `jws` against verifier.jwks_url (kid).        [authenticity]
   b. Recompute `binding.binding_digest` from this charge. [not replayed on another charge]
   c. Check now <= expires_at.                             [freshness]
   d. Require admission.verdict == "admit".                [admission]
   e. Require fast_gates all green.                        [enforcement continuity]
   f. Enforce effective_limit = min(static_cap, admission.dynamic_limit_usd).
4. Mint only if all pass. flag ⇒ hold for owner confirmation. deny ⇒ refuse.
```

## 4. `reason_code` vocabulary (deny / flag)

Derived from the AgentID constraint model (`specs/test-vectors-constraints.json`):

| reason_code | verdict | meaning |
|---|---|---|
| `scope_denied` | deny | action not in trust level's permission set (e.g. L1/L2 attempting payment) |
| `limit_exceeded` | deny | amount > min(trust default, owner custom) |
| `cooling_period` | deny | destination wallet inside first-seen cooling window |
| `dual_approval_required` | flag | amount over owner's dual-approval threshold; proceed only after owner confirms |
| `reputation_below_floor` | deny | behavioural risk above the level's tolerated floor |
| `identity_unresolvable` | deny | subject DID no longer resolves |
| `key_revoked` | deny | subject or platform key revoked/compromised |
| `certificate_expired` | deny | subject certificate outside validity window |

## 5. Canonicalization & signing

- `digest` and `jws` are computed over the object with `digest` and `jws` removed.
- Canonicalization is **JCS (RFC 8785)** — lexicographic key sort, no whitespace — so any
  implementation (Node, Python, Go, Rust) produces identical bytes.
- `jws` is compact EdDSA (`alg: EdDSA`, `typ: VerifierAttestation`, `kid: agentid-2026-03`).
- Public key resolvable at `https://getagentid.dev/.well-known/jwks.json`.

## 6. Live endpoint

`POST https://getagentid.dev/api/v1/agents/gateway/verifier-attestation`

```jsonc
// request
{ "subject_did": "did:web:getagentid.dev:agent:<id>",
  "charge_ref": "<gateway charge_ref>",
  "amount_usd": 50,
  "action_class": "irreversible",
  "action": "make_payment" }
// response: the signed verifier_attestation object above
```

## 7. Backward compatibility

The field is **optional** at every layer. A gateway that does not understand
`verifier_attestation` ignores it and enforces its own static caps — identical behaviour to
today. A verifier that is unreachable simply yields no field ⇒ un-gated. Clean degradation in
both directions, which is the property the v0.4 thread named as the design constraint.

## 8. A2A#1920 v0.4 alignment (pre-execution-verdict-v0)

This object is the verifier side of the three-part seam ratified on A2A#1920
(verifier `verifier_attestation` → gateway static caps + settlement → exactly-once guard):

- **`binding_digest` is byte-identical** to the converged gateway construction
  (`sha256(JCS({amount_usd, charge_ref, nonce, subject_did}))`, evidai/LemonCake), so a gateway
  recomputes and matches it at preflight. The four preflight checks (verify signature, recompute
  binding_digest, `verdict == "admit"`, `effective_budget = min(static_cap, dynamic_limit_usd)`)
  all read fields this object already emits.
- **`action_ref`** uses the `argentum-core action-ref-v1` preimage — byte-identical to
  SafeAgent's — so this admission joins a SafeAgent `COMMITTED` claim for the exactly-once /
  receipt layer without either side trusting the other. `action_ref_method` names the preimage
  per #1850 (the APS `draft-pidlisnyi-aps-01` preimage differs and would be named accordingly).
- **`nonce`** is the normative replay field; **`attestation_ref`** references the L1 attestation;
  **`verifier.key_source`** carries key provenance per #1829 (resolved via JWKS, not inline).
- **Receipt anchoring** (`execution_block_anchor`) is the on-chain rail's job; a fiat/off-chain
  rail correlates via `charge_ref` (offline-verifiable). This object is rail-agnostic.
