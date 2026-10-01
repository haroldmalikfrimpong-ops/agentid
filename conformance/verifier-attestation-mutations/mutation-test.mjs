#!/usr/bin/env node
/**
 * Independent mutation / negative test against AgentID's published verifier_attestation
 * conformance fixture (tests/verifier_attestation_fixture.json).
 *
 * Motivation: chopmob-cloud (A2A#1920, Jul 22) — "byte-reproducible on fresh clone" proves
 * producer/consumer agree on bytes, NOT that the verifier READS them. Their mutation test found
 * 28/114 published digests could be swapped for anything and still PASS. This runs the same
 * negative test against OUR vectors.
 *
 * The verifier here is INDEPENDENT of the generator: it reconstructs the signing pubkey from the
 * fixture's dev pubkey (base58 -> SPKI), and for ACCEPT it requires ALL of:
 *   (1) JWS EdDSA signature valid over header.body against that pubkey
 *   (2) header.kid == verifier.kid  (signing key bound to the claimed verifier)
 *   (3) JCS(core) == base64url-decode(jws.body)  (published object == the signed body)
 *   (4) published digest == sha256(JCS(core))     (digest checked, not assumed)
 *   (5) binding_digest == sha256(JCS({amount_usd, charge_ref, nonce, subject_did}))  (recomputed)
 *   (6) admission.verdict re-derived from policy inputs matches published verdict + reason_code
 *
 * Then it mutates every field of every attestation and asserts the verifier REJECTS each one.
 *
 * Run: node mutation-test.mjs  (reads ./verifier_attestation_fixture.json next to this file)
 */
import crypto from 'crypto'
import fs from 'fs'

const FIXTURE = new URL('./verifier_attestation_fixture.json', import.meta.url)
const DUAL = 500 // dual-approval threshold from the spec/generator

// --- JCS RFC 8785 — copied verbatim from build_verifier_attestation_fixture.mjs ---
function jcsSerialize(value) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!isFinite(value)) return 'null'
    return Object.is(value, -0) ? '0' : String(value)
  }
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(jcsSerialize).join(',') + ']'
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort()
    const pairs = keys.filter(k => value[k] !== undefined).map(k => JSON.stringify(k) + ':' + jcsSerialize(value[k]))
    return '{' + pairs.join(',') + '}'
  }
  return 'null'
}
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex')

// --- base58 decode (Bitcoin alphabet) ---
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function b58decode(str) {
  let n = 0n
  for (const ch of str) {
    const i = B58.indexOf(ch)
    if (i < 0) throw new Error('bad b58 char ' + ch)
    n = n * 58n + BigInt(i)
  }
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex
  let bytes = Buffer.from(hex, 'hex')
  // leading zeros
  let zeros = 0; for (const ch of str) { if (ch === '1') zeros++; else break }
  return Buffer.concat([Buffer.alloc(zeros), bytes])
}
// Ed25519 raw 32-byte pubkey -> SPKI DER -> KeyObject
function ed25519PubFromRaw(raw32) {
  const SPKI = Buffer.from('302a300506032b6570032100', 'hex')
  return crypto.createPublicKey({ key: Buffer.concat([SPKI, raw32]), format: 'der', type: 'spki' })
}

// --- re-derive the admission verdict from policy inputs (independent of published verdict) ---
// mirrors generator build(): deny if !permitted (scope), else deny if amount>limit, else flag if amount>DUAL, else admit
function deriveVerdict({ permitted, amount_usd, dynamic_limit_usd }) {
  if (!permitted) return { verdict: 'deny', reason_code: 'scope_denied' }
  if (dynamic_limit_usd != null && amount_usd > dynamic_limit_usd) return { verdict: 'deny', reason_code: 'limit_exceeded' }
  if (amount_usd > DUAL) return { verdict: 'flag', reason_code: 'dual_approval_required' }
  return { verdict: 'admit', reason_code: null }
}

// --- the independent verifier: returns {ok, reasons[]} ---
function verify(published, pubKey) {
  const reasons = []
  const { digest, jws, ...core } = published
  // (1)+(2)+(3) JWS
  try {
    const [h, b, s] = String(jws).split('.')
    if (!h || !b || !s) throw new Error('jws not 3 parts')
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'))
    const sigOk = crypto.verify(null, Buffer.from(`${h}.${b}`), pubKey, Buffer.from(s, 'base64url'))
    if (!sigOk) reasons.push('jws_signature_invalid')
    if (header.kid !== core.verifier?.kid) reasons.push('kid_mismatch_vs_verifier')
    const signedBody = Buffer.from(b, 'base64url').toString('utf8')
    if (jcsSerialize(core) !== signedBody) reasons.push('published_object_ne_signed_body')
  } catch (e) { reasons.push('jws_error:' + e.message) }
  // (4) digest
  if (digest !== sha256(jcsSerialize(core))) reasons.push('digest_mismatch')
  // (5) binding_digest recompute
  const bd = sha256(jcsSerialize({ amount_usd: core.binding?.amount_usd, charge_ref: core.binding?.charge_ref, nonce: core.binding?.nonce, subject_did: core.subject?.did }))
  if (bd !== core.binding?.binding_digest) reasons.push('binding_digest_mismatch')
  // (6) verdict re-derivation
  const d = deriveVerdict({ permitted: core.admission?.permitted, amount_usd: core.binding?.amount_usd, dynamic_limit_usd: core.admission?.dynamic_limit_usd })
  if (d.verdict !== core.admission?.verdict || d.reason_code !== core.admission?.reason_code) reasons.push('verdict_not_rederivable')
  return { ok: reasons.length === 0, reasons }
}

// deep clone helper
const clone = (o) => JSON.parse(JSON.stringify(o))

// --- mutation battery: each returns a mutated published object that MUST be rejected ---
function mutators(pub) {
  const out = []
  const add = (name, fn) => { const m = clone(pub); fn(m); out.push({ name, m }) }

  // chopmob failure shape (a): swap the published digest for garbage
  add('digest->garbage', m => { m.digest = 'f'.repeat(64) })
  // (b): swap binding_digest for garbage, leave bound fields
  add('binding_digest->garbage', m => { m.binding.binding_digest = '0'.repeat(64) })
  // (c): mutate a bound field, leave binding_digest+digest+jws (the "one-place-only" gap)
  add('amount_usd+1e6 (bound field, nothing else touched)', m => { m.binding.amount_usd += 1_000_000 })
  add('charge_ref swapped', m => { m.binding.charge_ref = 'lc_charge_ATTACKER' })
  add('nonce swapped', m => { m.binding.nonce = '11111111-1111-4111-8111-111111111111' })
  add('subject.did swapped', m => { m.subject.did = 'did:web:evil.example' })
  // (d): attacker fixes binding_digest to match the mutated amount, but cannot re-sign
  add('amount_usd+1e6 AND binding_digest recomputed (no re-sign)', m => {
    m.binding.amount_usd += 1_000_000
    m.binding.binding_digest = sha256(jcsSerialize({ amount_usd: m.binding.amount_usd, charge_ref: m.binding.charge_ref, nonce: m.binding.nonce, subject_did: m.subject.did }))
  })
  // verdict / authority escalations
  add('verdict deny/flag->admit', m => { m.admission.verdict = 'admit'; m.admission.reason_code = null })
  add('permitted false->true', m => { m.admission.permitted = true })
  add('dynamic_limit_usd inflated', m => { m.admission.dynamic_limit_usd = 100_000_000 })
  add('trust_level +1', m => { m.admission.trust_level = (m.admission.trust_level % 4) + 1 })
  // action_ref tamper (inside signed core)
  add('action_ref->garbage', m => { m.binding.action_ref = 'a'.repeat(64) })
  // fast_gates downgrade
  add('fast_gates.identity->spoofed', m => { m.fast_gates.identity = 'confirmed_but_lying'; })
  // freshness tamper
  add('expires_at extended', m => { m.expires_at = '2099-01-01T00:00:00.000Z' })
  // jws tamper: flip a char in the signature
  add('jws signature bit-flip', m => {
    const p = m.jws.split('.'); const sig = p[2]
    const i = 5; const c = sig[i] === 'A' ? 'B' : 'A'; p[2] = sig.slice(0, i) + c + sig.slice(i + 1); m.jws = p.join('.')
  })
  return out
}

// --- forged-issuer test: re-sign a mutated core with a DIFFERENT key, keep the claimed verifier/kid ---
function forgedIssuer(pub) {
  const { digest, jws, ...core } = clone(pub)
  // escalate: deny -> admit, inflate limit
  core.admission.verdict = 'admit'; core.admission.reason_code = null; core.admission.permitted = true
  core.admission.dynamic_limit_usd = 100_000_000
  // attacker recomputes binding_digest + digest honestly, and signs with THEIR key, spoofing kid
  core.binding.binding_digest = sha256(jcsSerialize({ amount_usd: core.binding.amount_usd, charge_ref: core.binding.charge_ref, nonce: core.binding.nonce, subject_did: core.subject.did }))
  const canonical = jcsSerialize(core)
  const newDigest = sha256(canonical)
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'VerifierAttestation', kid: core.verifier.kid })).toString('base64url')
  const body = Buffer.from(canonical).toString('base64url')
  const signature = crypto.sign(null, Buffer.from(`${header}.${body}`), privateKey).toString('base64url')
  return { ...core, digest: newDigest, jws: `${header}.${body}.${signature}` }
}

// ---- run ----
const fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'))
const pubKey = ed25519PubFromRaw(b58decode(fixture.dev_signing_pubkey_b58))

let totalMut = 0, caught = 0, baselineFail = 0
const escapes = []

for (const att of fixture.attestations) {
  const pub = att.verifier_attestation
  // baseline: the untampered attestation MUST verify
  const base = verify(pub, pubKey)
  if (!base.ok) { baselineFail++; console.log(`BASELINE FAIL [${att.scenario}]:`, base.reasons) }
  else console.log(`baseline OK   [${att.scenario}]`)

  const baseJson = JSON.stringify(pub)
  for (const { name, m } of mutators(pub)) {
    if (JSON.stringify(m) === baseJson) { continue } // no-op: field already held the target value; not a real mutation
    totalMut++
    const r = verify(m, pubKey)
    if (r.ok) { escapes.push(`${att.scenario} :: ${name}`); }
    else caught++
  }
  // forged issuer
  totalMut++
  const fr = verify(forgedIssuer(pub), pubKey)
  if (fr.ok) escapes.push(`${att.scenario} :: forged-issuer re-sign (wrong key, spoofed kid)`) ; else caught++
}

console.log('\n================ RESULT ================')
console.log(`attestations:            ${fixture.attestations.length}`)
console.log(`baseline verifies:       ${fixture.attestations.length - baselineFail}/${fixture.attestations.length}`)
console.log(`mutations attempted:     ${totalMut}`)
console.log(`mutations REJECTED:      ${caught}/${totalMut}`)
console.log(`mutations that ESCAPED:  ${escapes.length}`)
if (escapes.length) { console.log('\nESCAPES:'); escapes.forEach(e => console.log('  - ' + e)) }
console.log('=======================================')
