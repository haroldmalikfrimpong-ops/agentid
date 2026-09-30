# The `did:agentid` DID Method v1.0

**Author:** AgentID (@haroldmalikfrimpong-ops)
**Status:** DRAFT — implemented at getagentid.dev; registry entry pending
**Date:** 2026-09-30
**Spec ID:** DID-AGENTID-1
**Rendered:** https://getagentid.dev/specs/did-method-agentid-v1.0
**Canonical source:** https://github.com/haroldmalikfrimpong-ops/agentid/blob/main/specs/did-method-agentid-v1.0.md

## Abstract

`did:agentid` is a [W3C Decentralized Identifier](https://www.w3.org/TR/did-core/) method for AI agents registered in the AgentID registry at `getagentid.dev`. The method-specific identifier is the server-assigned AgentID `agent_id`. Every `did:agentid` identifier has an exact `did:web` equivalent (`did:web:getagentid.dev:agent:<agent_id>`); both forms resolve to the same DID document, and each document lists the other form in `alsoKnownAs`. This lets verifiers that only support `did:web` resolve AgentID agents today, while giving agents a short, method-native identifier that is independent of the `did:web` path layout.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "MAY" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Status of This Document

This is version 1.0 of the method specification. The resolver, the `alsoKnownAs` cross-links, and the certificate endpoint described here are live at `getagentid.dev`. The entry in the W3C DID Extensions registry (§10) has been drafted but not yet submitted.

## 2. Method Name

The name string that identifies this DID method is `agentid`.

A DID that uses this method MUST begin with the prefix `did:agentid:`. Per DID Core, the prefix is lowercase. The remainder of the DID, after the prefix, is the method-specific identifier described in §3.

## 3. Method-Specific Identifier

The method-specific identifier is the AgentID `agent_id`: the literal string `agent_` followed by exactly 16 lowercase hexadecimal characters (64 bits of server-generated randomness).

```abnf
agentid-did   = "did:agentid:" agent-id
agent-id      = "agent_" 16lowerhex
lowerhex      = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"
```

Example:

```
did:agentid:agent_d1b7ef01f9af191f
```

Rules:

- The identifier is assigned by the registry at registration (§6.1). Clients MUST NOT self-mint `agent_id` values.
- Uppercase hexadecimal is not permitted. Resolvers MUST reject identifiers that do not match the ABNF with the `invalidDid` error (§6.2).
- Identifiers are globally unique within the `getagentid.dev` registry and are never reused after deactivation.
- DID URL components (path, query, fragment) follow DID Core. Fragments identify verification methods and services within the document, e.g. `did:agentid:agent_d1b7ef01f9af191f#ed25519-key-1`.

## 4. Target System

The verifiable data registry for `did:agentid` is the AgentID registry operated at `https://getagentid.dev`. It is a server-held registry (a hosted database behind an HTTPS API), not a distributed ledger. The registry:

- assigns `agent_id` values and issues an ECDSA P-256 identity certificate at registration;
- stores the agent's bound public keys (ECDSA P-256 always; Ed25519 once bound), wallet bindings, capabilities, and metadata;
- serves DID documents and DID Resolution Results over HTTPS;
- signs receipts, trust headers, and credentials about agents under the issuer DID `did:web:getagentid.dev` (platform Ed25519 key, kid `agentid-2026-03`, published at `https://getagentid.dev/.well-known/jwks.json` and `https://getagentid.dev/.well-known/did.json`).

### 4.1 `did:web` equivalence

For every registered agent the following two DIDs are equivalent and MUST resolve to the same verification material and services:

| Form | Identifier | Resolved from |
|------|-----------|---------------|
| native | `did:agentid:<agent_id>` | `https://getagentid.dev/1.0/identifiers/did%3Aagentid%3A<agent_id>` |
| did:web | `did:web:getagentid.dev:agent:<agent_id>` | `https://getagentid.dev/agent/<agent_id>/did.json` (did:web path rule) or the resolver above |

The two documents differ only in the `id`, `controller`, and the `id` prefixes of verification methods and services. Each lists the other in `alsoKnownAs`. Verifiers MAY treat a signature keyed by `did:web:getagentid.dev:agent:X#ed25519-key-1` as equivalent to one keyed by `did:agentid:X#ed25519-key-1` after confirming the `alsoKnownAs` link in either direction.

## 5. DID Document

### 5.1 Shape

A `did:agentid` DID document conforms to DID Core 1.0 and contains:

| Property | Value |
|----------|-------|
| `@context` | `["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed2020/v1"]` |
| `id` | `did:agentid:<agent_id>` |
| `controller` | `did:web:getagentid.dev` — the registry that assigned the identifier |
| `alsoKnownAs` | `["did:web:getagentid.dev:agent:<agent_id>"]` |
| `verificationMethod` | `#ecdsa-key-1` (`EcdsaSecp256r1VerificationKey2019`, `publicKeyPem`) — always present. `#ed25519-key-1` (`Ed25519VerificationKey2020`, `publicKeyHex`, 32 bytes) — present once the agent has bound an Ed25519 key (trust level L2 or higher). |
| `authentication`, `assertionMethod` | references to every verification method |
| `service` | `AgentIDVerification`, `AgentIDCredibilityPacket`, `AgentIDProofHistory`, `AgentTrustScore`, `AgentIDMerkleRoot`; `AgentCapability` when capabilities are declared; `SolanaWallet` when a wallet is bound |
| `metadata` | AgentID extension: `name`, `description`, `owner`, `platform`, `capabilities`, `limitations`, `social_links` |

The `did:web` form is identical except `id` and every `#fragment` id use the `did:web:getagentid.dev:agent:<agent_id>` prefix, `controller` is the document's own `id`, and `alsoKnownAs` carries the `did:agentid` form.

### 5.2 Example — `did:agentid:agent_d1b7ef01f9af191f`

Live agent, public key material only. Retrieved 2026-09-30 from `https://getagentid.dev/agent/agent_d1b7ef01f9af191f/did.json` and re-expressed in the `did:agentid` form.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed2020/v1"
  ],
  "id": "did:agentid:agent_d1b7ef01f9af191f",
  "controller": "did:web:getagentid.dev",
  "alsoKnownAs": ["did:web:getagentid.dev:agent:agent_d1b7ef01f9af191f"],
  "verificationMethod": [
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#ecdsa-key-1",
      "type": "EcdsaSecp256r1VerificationKey2019",
      "controller": "did:agentid:agent_d1b7ef01f9af191f",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/merQ0Wku/E2x8wma9LSPW9XkvkH\nxK06ciqmZnEBOytwkYrW9gx6k2asBSDlnglbE39Clr3Netu8n8GSEgE8TQ==\n-----END PUBLIC KEY-----\n"
    },
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#ed25519-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:agentid:agent_d1b7ef01f9af191f",
      "publicKeyHex": "847888e3e256e58d2f8c3d8d9a16e0e72e0662b3802965eaea29a4ddabe73338"
    }
  ],
  "authentication": [
    "did:agentid:agent_d1b7ef01f9af191f#ecdsa-key-1",
    "did:agentid:agent_d1b7ef01f9af191f#ed25519-key-1"
  ],
  "assertionMethod": [
    "did:agentid:agent_d1b7ef01f9af191f#ecdsa-key-1",
    "did:agentid:agent_d1b7ef01f9af191f#ed25519-key-1"
  ],
  "service": [
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#agentid-verify",
      "type": "AgentIDVerification",
      "serviceEndpoint": "https://getagentid.dev/api/v1/agents/verify",
      "description": "Verify this agent's identity, trust level, and behavioural risk score"
    },
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#credibility-packet",
      "type": "AgentIDCredibilityPacket",
      "serviceEndpoint": "https://getagentid.dev/api/v1/agents/credibility-packet?agent_id=agent_d1b7ef01f9af191f",
      "description": "Signed portable trust resume — offline verifiable"
    },
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#proof-history",
      "type": "AgentIDProofHistory",
      "serviceEndpoint": "https://getagentid.dev/api/v1/agents/credibility-packet?agent_id=agent_d1b7ef01f9af191f",
      "description": "Signed execution receipts, attestation count, negative/resolved signals, scarring score — independently verifiable"
    },
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#trust-header",
      "type": "AgentTrustScore",
      "serviceEndpoint": "https://getagentid.dev/api/v1/agents/trust-header?agent_id=agent_d1b7ef01f9af191f",
      "description": "Signed 1-hour JWT for Agent-Trust-Score HTTP header"
    },
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#merkle-root",
      "type": "AgentIDMerkleRoot",
      "serviceEndpoint": "https://getagentid.dev/api/v1/agents/merkle-root?agent_id=agent_d1b7ef01f9af191f",
      "description": "Merkle root over all receipts — supports O(log n) inclusion proofs"
    },
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#capabilities",
      "type": "AgentCapability",
      "serviceEndpoint": "https://getagentid.dev/api/v1/agents/discover?capability=code",
      "capabilities": ["code", "deploy", "test", "git", "architecture", "thread-response"],
      "description": "Agent capabilities: code, deploy, test, git, architecture, thread-response"
    },
    {
      "id": "did:agentid:agent_d1b7ef01f9af191f#solana-wallet",
      "type": "SolanaWallet",
      "serviceEndpoint": "https://explorer.solana.com/address/9v7RDuHrjansLurSG8eM2HPaxafrjMtyGL4uaksCcDuR?cluster=devnet",
      "chain": "solana",
      "address": "9v7RDuHrjansLurSG8eM2HPaxafrjMtyGL4uaksCcDuR"
    }
  ],
  "metadata": {
    "name": "Claude Code Consigliere",
    "description": "Malik's AI development assistant. Manages AgentID, 1Stop, Sales Agent, Trading Bot. Always-on daemon across sessions.",
    "owner": "AgentID",
    "platform": null,
    "capabilities": ["code", "deploy", "test", "git", "architecture", "thread-response"],
    "limitations": [],
    "social_links": null
  }
}
```

### 5.3 Issuer document

The controller `did:web:getagentid.dev` resolves (via `https://getagentid.dev/.well-known/did.json` or the resolver in §6.2) to a document whose single verification method is the platform Ed25519 signing key:

```json
{
  "id": "did:web:getagentid.dev#agentid-2026-03",
  "type": "JsonWebKey2020",
  "controller": "did:web:getagentid.dev",
  "publicKeyJwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "xdpmjfq2DX4d6yML7QjaSkYB2h9Dm3phwts5gkAPBp8",
    "kid": "agentid-2026-03",
    "use": "sig",
    "alg": "EdDSA"
  }
}
```

This is the key that signs AgentID receipts, trust headers, and credentials. It is the same key served by `https://getagentid.dev/.well-known/jwks.json`.

## 6. Operations

### 6.1 Create

A `did:agentid` identifier is created by registering an agent:

```
POST https://getagentid.dev/api/v1/agents/register
Authorization: Bearer <api key>
Content-Type: application/json

{ "name": "...", "owner": "...", "capabilities": ["..."] }
```

The registry generates the `agent_id` (`agent_` + 16 lowercase hex), generates an ECDSA P-256 keypair, issues a signed identity certificate, and stores the agent as active at trust level L1. The response includes `agent_id`; the DID is `did:agentid:<agent_id>`. The identifier is server-assigned and MUST NOT be chosen by the client.

### 6.2 Read (Resolve)

`did:agentid` is resolved over HTTPS using the [DID Resolution v0.3](https://w3c-ccg.github.io/did-resolution/) HTTP(S) binding (the DIF Universal Resolver interface):

```
GET https://getagentid.dev/1.0/identifiers/{did}
```

`{did}` is the percent-encoded DID. Example:

```
GET https://getagentid.dev/1.0/identifiers/did%3Aagentid%3Aagent_d1b7ef01f9af191f
Accept: application/ld+json;profile="https://w3id.org/did-resolution"
```

Response (`200 OK`, `Content-Type: application/ld+json;profile="https://w3id.org/did-resolution"`):

```json
{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": { "...": "as in §5.2" },
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json",
    "did": {
      "didString": "did:agentid:agent_d1b7ef01f9af191f",
      "methodSpecificId": "agent_d1b7ef01f9af191f",
      "method": "agentid"
    },
    "retrieved": "2026-09-30T12:00:00.000Z"
  },
  "didDocumentMetadata": {
    "created": "2026-03-27T10:15:42.117Z",
    "updated": "2026-04-02T08:31:09.402Z",
    "deactivated": false
  }
}
```

`created` is the registration time. `updated` is the time of the last change that affected the document (Ed25519 key binding, wallet binding, or metadata change), falling back to `created`.

The same endpoint also resolves the `did:web` forms `did:web:getagentid.dev:agent:<agent_id>` and `did:web:getagentid.dev`.

Errors are reported in `didResolutionMetadata.error` with `didDocument: null`:

| `error` | HTTP status | When |
|---------|-------------|------|
| `invalidDid` | 400 | not `did:<method>:<id>`, or the `did:agentid` identifier does not match the ABNF in §3 |
| `notFound` | 404 | well-formed identifier with no registered agent (also used for `did:web` identifiers outside `getagentid.dev`) |
| `methodNotSupported` | 501 | any method other than `agentid` or `web` |

**Deactivated agents.** If the agent has been set inactive (§6.4) the resolver still returns the last document (so historical receipts remain verifiable) with `didDocumentMetadata.deactivated: true`. Verifiers MUST treat a deactivated document as not authoritative for new authentication.

**Working-group profile.** The working-group DID resolution spec (corpollc/qntm, `specs/working-group/did-resolution.md` §3.4) lists `did:agentid` as RECOMMENDED with two paths: *local resolution* (a cached `agent_id` → Ed25519 key binding, for agents in the same trust domain) and *remote resolution* against `https://getagentid.dev/api/v1/agents/<identifier>/certificate`. Both are supported:

- **Local resolution** is implemented by the reference resolver `sdk/python/agentid/did.py` (`resolve_did_agentid`, `register_agentid_key`) in the public AgentID SDK. It returns the raw 32-byte Ed25519 public key from an in-process registry and makes no network call.
- **Remote resolution** is served by `GET https://getagentid.dev/api/v1/agents/<agent_id>/certificate`, which returns the agent's Ed25519 public key (`ed25519_public_key`, hex), the signed Ed25519 binding certificate and its expiry, the ECDSA identity certificate, the trust score, and links to the DID document and this resolver. The key returned there MUST equal `publicKeyHex` of `#ed25519-key-1` in the resolved document.

Implementations SHOULD prefer local resolution when the binding is cached and fall back to remote resolution. Either way, the DID Resolution Result above is the authoritative representation; the certificate endpoint is a convenience projection of the same registry row.

**Fast path for verifiers that only speak `did:web`.** Rewrite `did:agentid:<agent_id>` to `did:web:getagentid.dev:agent:<agent_id>` and resolve with any conformant `did:web` resolver. The document you get lists the original `did:agentid` in `alsoKnownAs`.

### 6.3 Update

The registry holder (the agent's owner, authenticated by API key) updates the document through the AgentID API:

- **Key binding / rotation** — `POST https://getagentid.dev/api/v1/agents/bind-ed25519` with `{ agent_id, ed25519_public_key }` (64 hex characters). This sets or replaces `#ed25519-key-1` (`publicKeyHex`), replaces the Ed25519 binding certificate, derives and sets the Solana address that appears in the `#solana-wallet` service (the 32-byte Ed25519 key *is* the Solana address in base58), and raises the trust level to at least L2. The previous Ed25519 key is not retained in the document; verifiers needing the old key for historical material should use the signed receipts and credibility packet, which embed the key that was current at signing time.
- **Wallet binding** — `POST /api/v1/agents/bind-wallet` adds or changes the `#solana-wallet` service.
- **Metadata** — `POST /api/v1/agents/update-metadata` changes `metadata.social_links` and other descriptive fields.

There is no client-side document upload: the document is always derived from the registry state, and `didDocumentMetadata.updated` moves on each of the changes above. The ECDSA identity key `#ecdsa-key-1` is fixed at registration and cannot be rotated in v1.0.

### 6.4 Deactivate

An agent is deactivated when the registry sets it inactive (owner request, platform abuse action, or account closure). Effects:

- `GET /agent/<agent_id>/did.json` returns `404` (the did:web path form only serves active agents).
- `GET /1.0/identifiers/did%3Aagentid%3A<agent_id>` returns the last document with `didDocumentMetadata.deactivated: true`.
- `POST /api/v1/agents/verify` returns `verified: false`, `active: false`.

Deactivation is not reversible through the public API in v1.0, and the `agent_id` is never reissued.

## 7. Security Considerations

**Trust root.** `did:agentid` trusts the operator of `getagentid.dev` and the Web PKI that secures HTTPS to it, exactly as `did:web` does. There is no on-chain anchor for the document itself; a compromise of the registry or its TLS could serve a substituted key. Mitigations: (a) the issuer key is published redundantly at `/.well-known/jwks.json` and `/.well-known/did.json` and pinned by kid `agentid-2026-03` in every signed artefact; (b) action receipts are hash-chained and Merkle-rooted (`AgentIDMerkleRoot` service) and can be published on Solana via `/api/v1/agents/publish-onchain`, so tampering with history is detectable even if the current document is not independently anchored; (c) the Ed25519 binding certificate is signed at bind time and returned by the certificate endpoint, giving verifiers a second, timestamped statement of the key.

**Server-held registry.** Identifiers are server-assigned and the registry is the single writer. This removes squatting and collision attacks on the identifier space but means availability of resolution depends on `getagentid.dev`. Resolvers SHOULD cache documents (the server sets `Cache-Control: public, max-age=300`) and SHOULD honour `deactivated` on refresh.

**Key rotation.** Binding a new Ed25519 key replaces the old one in the document (§6.3). Verifiers that need to validate signatures produced under a previous key MUST use the signed receipt or credibility packet from that time rather than re-resolving the current document. Rotating the ECDSA identity key is not supported in v1.0.

**Replay and freshness.** A DID document proves key ownership, not liveness. Callers MUST bind a resolved key to a fresh challenge (`/api/v1/agents/challenge`) or a signed action reference with an epoch/nonce before granting authority. The `AgentTrustScore` service issues 1-hour JWTs; treat anything older as stale. `didResolutionMetadata.retrieved` records when the server produced the result.

**`did:web` equivalence.** Because both forms are derived from the same registry row, there is exactly one set of keys per agent and no possibility of the two forms diverging. The equivalence is asserted in both directions via `alsoKnownAs`, and a verifier SHOULD check that link before treating the two identifiers as the same subject. A `did:web` document fetched over plain HTTPS and a resolver result carry the same material; neither is "more trusted".

**Trust levels are not in the document.** Trust level (L1–L4) is a registry judgement and changes over time, so it is exposed through the `AgentIDVerification` and `AgentTrustScore` services rather than as a DID document property. Do not infer trust from the presence of `#ed25519-key-1` alone.

## 8. Privacy Considerations

A `did:agentid` document reveals: the agent's public keys, its declared name, description, owner label, platform, capabilities, limitations, optional social links, and (if bound) a Solana wallet address. It does not contain human names, emails, or account identifiers of the operator; the `owner` field is a free-text label chosen at registration and SHOULD NOT contain personal data. Resolution requests are ordinary HTTPS requests to `getagentid.dev` and are subject to the platform's logging; there is no correlation identifier beyond the DID itself. Wallet addresses are inherently correlatable on their chain; agents that do not want that linkage should not bind a wallet.

## 9. Conformance

- **DID Core 1.0** — documents use `@context`, `id`, `controller`, `alsoKnownAs`, `verificationMethod`, `authentication`, `assertionMethod`, `service` as defined; `metadata` is a method-specific extension property.
- **DID Resolution v0.3, HTTP(S) binding** — `GET /1.0/identifiers/{did}` returns a DID Resolution Result with `didResolutionMetadata`, `didDocumentMetadata`, the `application/ld+json;profile="https://w3id.org/did-resolution"` media type, and the `invalidDid` / `notFound` / `methodNotSupported` error codes.
- **did:web** — the equivalent form follows the did:web path rule (`/agent/<agent_id>/did.json`) and the well-known rule for the issuer (`/.well-known/did.json`).
- **Verification suites** — `EcdsaSecp256r1VerificationKey2019` with `publicKeyPem`; `Ed25519VerificationKey2020` with `publicKeyHex` (32 bytes, lowercase hex). Consumers that expect `publicKeyMultibase` can derive it as `z` + base58btc(`0xed01` ‖ key).

## 10. Registry Entry (w3c/did-extensions)

Proposed content of `methods/agentid.json`:

```json
{
  "name": "agentid",
  "status": "registered",
  "verifiableDataRegistry": "getagentid.dev",
  "contactName": "Michael Malik Ematuwo",
  "contactEmail": "TODO(malik)",
  "contactWebsite": "https://getagentid.dev",
  "specification": "https://getagentid.dev/specs/did-method-agentid-v1.0"
}
```

## 11. References

- W3C, *Decentralized Identifiers (DIDs) v1.0* — https://www.w3.org/TR/did-core/
- W3C CCG, *DID Resolution v0.3* — https://w3c-ccg.github.io/did-resolution/
- W3C CCG, *did:web Method Specification* — https://w3c-ccg.github.io/did-method-web/
- W3C, *DID Extensions* registry — https://github.com/w3c/did-extensions
- corpollc/qntm, *Working Group DID Resolution* §3.4 `did:agentid` — https://github.com/corpollc/qntm/blob/main/specs/working-group/did-resolution.md
- AgentID SDK reference resolver — https://github.com/haroldmalikfrimpong-ops/agentid/blob/main/sdk/python/agentid/did.py
- AgentID, *Agent Trust Levels v1.0* — https://getagentid.dev/specs/trust-levels-v1.0
