/**
 * Capsule crypto envelope: construction and opening.
 *
 * QUANTUM-PLAN Phase 2 (key handling) + Phase 3 (the `link` factor).
 *
 * ── The model ────────────────────────────────────────────────────────────
 *
 * Every capsule has ONE random 256-bit key `K_c`. Content is encrypted under
 * keys derived from it. `K_c` is never stored; it is RECONSTRUCTED at open
 * time from one share per required factor:
 *
 *     K_c = HKDF(salt, s₁‖s₂‖…‖sₙ ‖ ct₁‖…‖ctₙ ‖ pk₁‖…‖pkₙ, info)
 *
 * A capsule is post-quantum if AT LEAST ONE of its required factors is. That
 * is the entire design goal: breaking the `time` factor's pairing crypto is
 * not enough while a `link` or `secret` share is still unknown.
 *
 * ── Why the combiner looks like this ─────────────────────────────────────
 *
 * NIST SP 800-227 §4.6.3 (final, Sept 2025) states that a combiner over the
 * shared secrets ALONE "does not preserve IND-CCA security, regardless of the
 * properties of the KDF". An earlier draft of this plan used exactly that
 * shape and therefore claimed a property it did not deliver. The approved
 * construction additionally binds the wrapping ciphertexts, the wrapping
 * public keys and a domain separator, which is what `draft-ietf-lamps-pq-
 * composite-kem` does too.
 *
 * Every variable-length field is LENGTH-PREFIXED. SP 800-227 p.29 names the
 * bug this prevents: with variable-length inputs, plain concatenation can
 * collide, so a two-factor split could otherwise produce the same key as a
 * three-factor one.
 *
 * ── Why there is a separate commitment ───────────────────────────────────
 *
 * AES-GCM is NOT key-committing (RFC 9771, CFRG, May 2025). Without a
 * commitment a capsule could open to DIFFERENT valid content down different
 * recovery paths, which would destroy the only promise the product makes.
 * `commit` binds the ciphertext to exactly one `K_c`.
 *
 * ── Why the header is MAC'd ──────────────────────────────────────────────
 *
 * Otherwise the factor list is editable and an attacker strips a required
 * factor: a downgrade attack. age HMACs its whole header; JWE makes the
 * protected header the AAD and RFC 7516 §11.4 names this exact attack.
 *
 * ── Why the domain separator is not the capsule id ────────────────────────
 *
 * The combiner and the header MAC are domain-separated by an `envelopeId`, and
 * it is deliberately NOT `capsule.id`. The canister assigns `CAP<n>` inside the
 * create call, so at SEAL time the client does not know it — an envelope keyed
 * on it could not be built before the capsule existed, and a two-phase create
 * would leave a window where a capsule row exists with no envelope.
 *
 * `envelopeId` is instead the hex of the capsule's vetKD identity (the
 * `encryptionId`): 32 client-generated random bytes that the canister already
 * enforces as globally unique (`usedEncryptionIds`), and that are stored on the
 * envelope as `timeIdentity` so the open path recovers the same value without
 * trusting anything the caller passes in. Use `envelopeIdFor()` at both ends.
 */

import type { CapsuleCrypto, CryptoFactor } from './types';
import {
  SUPPORTED_CRYPTO_VERSION,
  ATTACHMENT_KEY_V2_MAGIC,
  ATTACHMENT_KEY_V2_BYTES,
  isEnvelopeWrappedAttachmentKey,
} from './capsuleFormat';

const KEY_BYTES = 32;
const IV_BYTES = 12;

const LABEL_MESSAGE = 'capsl/v1/message';
const LABEL_ATTACHMENT = 'capsl/v1/attachment/';
const LABEL_COMMIT = 'capsl/v1/commit';
const LABEL_HEADER = 'capsl/v1/header';
const LABEL_CAPSULE_KEY = 'capsl/v1/capsule-key';
const LABEL_LINK_FACTOR = 'capsl/v1/factor/link';

const utf8 = (s: string) => new TextEncoder().encode(s);

/**
 * The envelope's domain separator: lowercase hex of the vetKD identity.
 *
 * Both the seal and the open path derive it from the same bytes — the seal path
 * from the `encryptionId` it just generated, the open path from the stored
 * `crypto.timeIdentity` — so the two can never disagree. See the module header
 * for why this is not `capsule.id`.
 */
export function envelopeIdFor(timeIdentity: Uint8Array): string {
  let out = '';
  for (const b of timeIdentity) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Big-endian u32 length prefix. Fixed width, so prefixes never collide. */
function lengthPrefixed(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += 4 + p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    new DataView(out.buffer, out.byteOffset + o, 4).setUint32(0, p.length, false);
    o += 4;
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Constant-time comparison. Never short-circuits on the first difference. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  bytes = KEY_BYTES,
): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: info as BufferSource },
    base,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    'raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data as BufferSource));
}

async function aesKey(raw: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM', length: 256 }, false, usage);
}

// ── Factors ─────────────────────────────────────────────────────────────────

/**
 * A factor at SEAL time. Produces a share plus whatever must be stored to
 * recover it later.
 *
 * `ciphertext` is empty for factors whose share is derived from a secret the
 * holder already has (`link`, `secret`) — there is nothing to store, which is
 * exactly what makes those factors post-quantum.
 */
export interface FactorSealer {
  kind: string;
  seal(): Promise<{ share: Uint8Array; ciphertext: Uint8Array; publicKey: Uint8Array }>;
}

/** The same factor at OPEN time. */
export interface FactorOpener {
  kind: string;
  open(ciphertext: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>;
}

/**
 * `link` factor: the share is derived from a secret carried in the claim
 * URL's FRAGMENT, which browsers never transmit to a server.
 *
 * Post-quantum for free and with no key-custody burden the product does not
 * already have: the recipient already has to keep the link.
 */
export function linkSealer(linkSecret: Uint8Array): FactorSealer {
  return {
    kind: 'link',
    async seal() {
      return {
        share: await hkdf(linkSecret, new Uint8Array(0), utf8(LABEL_LINK_FACTOR)),
        ciphertext: new Uint8Array(0),
        publicKey: new Uint8Array(0),
      };
    },
  };
}

export function linkOpener(linkSecret: Uint8Array): FactorOpener {
  return {
    kind: 'link',
    async open() {
      return hkdf(linkSecret, new Uint8Array(0), utf8(LABEL_LINK_FACTOR));
    },
  };
}

/** Generate a fresh 256-bit link secret for a new claimable capsule. */
export function generateLinkSecret(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

/**
 * `time` factor: a random share wrapped so only the release network can
 * return it, and only once the capsule's unlock conditions are met.
 *
 * The wrap/unwrap functions are injected rather than imported so this module
 * stays free of @dfinity/vetkeys and is unit-testable without a canister.
 */
export function timeSealer(
  wrap: (share: Uint8Array) => Promise<{ ciphertext: Uint8Array; publicKey: Uint8Array }>,
): FactorSealer {
  return {
    kind: 'time',
    async seal() {
      const share = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
      const { ciphertext, publicKey } = await wrap(share);
      return { share, ciphertext, publicKey };
    },
  };
}

export function timeOpener(
  unwrap: (ciphertext: Uint8Array, publicKey: Uint8Array) => Promise<Uint8Array>,
): FactorOpener {
  return { kind: 'time', open: unwrap };
}

// ── Combiner ────────────────────────────────────────────────────────────────

/**
 * Reconstruct `K_c` from the factor shares.
 *
 * Binds, in this order and all length-prefixed: every share, every wrapping
 * ciphertext, every wrapping public key. Salted with the format version and
 * the ordered factor-kind list, and domain-separated by the envelope id — so an
 * envelope's key is useless in any other envelope.
 */
async function combine(
  version: number,
  envelopeId: string,
  kinds: string[],
  shares: Uint8Array[],
  ciphertexts: Uint8Array[],
  publicKeys: Uint8Array[],
): Promise<Uint8Array> {
  const salt = lengthPrefixed([utf8(String(version)), utf8(kinds.join('|'))]);
  const ikm = lengthPrefixed([...shares, ...ciphertexts, ...publicKeys]);
  const info = lengthPrefixed([utf8(LABEL_CAPSULE_KEY), utf8(envelopeId)]);
  return hkdf(ikm, salt, info);
}

/** Canonical header bytes, the exact input the header MAC covers. */
function canonicalHeader(version: number, envelopeId: string, factors: CryptoFactor[], layers: CapsuleCrypto['layers']): Uint8Array {
  const parts: Uint8Array[] = [utf8(String(version)), utf8(envelopeId)];
  for (const f of factors) { parts.push(utf8(f.kind)); parts.push(f.params); }
  for (const l of layers) { parts.push(utf8(l.alg)); parts.push(l.innerCommit); }
  return lengthPrefixed(parts);
}

// ── Seal / open ─────────────────────────────────────────────────────────────

export interface SealResult {
  crypto: CapsuleCrypto;
  /** Retained so the caller can derive attachment keys for the same capsule. */
  capsuleKey: Uint8Array;
}

/**
 * Encrypt `plaintext` into a versioned envelope protected by ALL of `factors`.
 *
 * Throws on an empty factor list: a capsule with no factors is not encrypted,
 * and producing one silently would be the worst possible failure here.
 */
export async function sealCapsule(
  envelopeId: string,
  plaintext: string,
  factors: FactorSealer[],
): Promise<SealResult> {
  if (factors.length === 0) throw new Error('A capsule must have at least one factor.');

  const sealed = await Promise.all(factors.map((f) => f.seal()));
  const kinds = factors.map((f) => f.kind);
  const shares = sealed.map((s) => s.share);
  const ciphertexts = sealed.map((s) => s.ciphertext);
  const publicKeys = sealed.map((s) => s.publicKey);

  const capsuleKey = await combine(SUPPORTED_CRYPTO_VERSION, envelopeId, kinds, shares, ciphertexts, publicKeys);

  const messageKey = await hkdf(capsuleKey, new Uint8Array(0), utf8(LABEL_MESSAGE));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const body = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      await aesKey(messageKey, ['encrypt']),
      utf8(plaintext) as BufferSource,
    ),
  );
  // IV is prepended rather than stored separately: one blob, one thing to
  // carry, and no way to pair the wrong IV with a ciphertext.
  const ciphertext = concat([iv, body]);

  const cryptoFactors: CryptoFactor[] = factors.map((f, i) => ({
    kind: f.kind,
    params: lengthPrefixed([ciphertexts[i], publicKeys[i]]),
  }));

  const commit = await hkdf(capsuleKey, new Uint8Array(0), utf8(LABEL_COMMIT));
  const headerKey = await hkdf(capsuleKey, new Uint8Array(0), utf8(LABEL_HEADER));
  const headerMac = await hmac(headerKey, canonicalHeader(SUPPORTED_CRYPTO_VERSION, envelopeId, cryptoFactors, []));

  return {
    capsuleKey,
    crypto: {
      version: SUPPORTED_CRYPTO_VERSION,
      factors: cryptoFactors,
      layers: [],
      headerMac,
      ciphertext,
      commit,
      timeIdentity: undefined,
      ext: [],
    },
  };
}

/** Split a `params` blob back into its ciphertext and public key. */
function splitParams(params: Uint8Array): { ciphertext: Uint8Array; publicKey: Uint8Array } {
  const view = new DataView(params.buffer, params.byteOffset, params.byteLength);
  const ctLen = view.getUint32(0, false);
  const ciphertext = params.slice(4, 4 + ctLen);
  const pkLen = view.getUint32(4 + ctLen, false);
  const publicKey = params.slice(8 + ctLen, 8 + ctLen + pkLen);
  return { ciphertext, publicKey };
}

export class EnvelopeIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnvelopeIntegrityError';
  }
}

/**
 * Open an envelope. Requires an opener for EVERY factor, in the same order.
 *
 * Verification order matters: header MAC before anything is trusted, then the
 * key commitment, then the AEAD. Each step is a distinct, named failure so a
 * tampered capsule never surfaces as a generic decrypt error.
 */
export interface OpenResult {
  plaintext: string;
  /**
   * `K_c`, so the caller can unwrap this capsule's attachment keys without a
   * second factor-combination pass. Mirrors `SealResult.capsuleKey`.
   *
   * ⚠️ RETURNED RATHER THAN RE-DERIVED ON PURPOSE. Re-running the combiner at
   * the attachment site would mean a second copy of the factor-order and
   * header-MAC logic, which is the duplicated-judgement defect this repo has
   * shipped repeatedly — and here the second copy would decide whether
   * somebody's attachment decrypts.
   */
  capsuleKey: Uint8Array;
}

export async function openCapsule(
  envelopeId: string,
  envelope: CapsuleCrypto,
  openers: FactorOpener[],
): Promise<OpenResult> {
  if (openers.length !== envelope.factors.length) {
    throw new EnvelopeIntegrityError(
      `This capsule needs ${envelope.factors.length} factor(s) to open; ${openers.length} supplied.`,
    );
  }

  const kinds = envelope.factors.map((f) => f.kind);
  const ciphertexts: Uint8Array[] = [];
  const publicKeys: Uint8Array[] = [];
  const shares: Uint8Array[] = [];

  for (let i = 0; i < envelope.factors.length; i++) {
    const factor = envelope.factors[i];
    const opener = openers[i];
    if (opener.kind !== factor.kind) {
      throw new EnvelopeIntegrityError(`Factor ${i} is "${factor.kind}" but a "${opener.kind}" opener was supplied.`);
    }
    const { ciphertext, publicKey } = splitParams(factor.params);
    ciphertexts.push(ciphertext);
    publicKeys.push(publicKey);
    shares.push(await opener.open(ciphertext, publicKey));
  }

  const capsuleKey = await combine(envelope.version, envelopeId, kinds, shares, ciphertexts, publicKeys);
  return openWithCapsuleKey(envelopeId, envelope, capsuleKey);
}

/**
 * The half of opening that needs only `K_c` — no factors, and therefore no vetKD
 * derivation.
 *
 * 🔴 **EXTRACTED SO THE WRAPPED-KEY PATH CANNOT SKIP THE CHECKS.** A capsule key
 * recovered from a stored wrap (`utils/capsuleKeyWrap.ts`) arrives without any
 * factor ever being opened, and the tempting shortcut is to decrypt with it and
 * be done. Both verifications below are what make that safe, and the commitment
 * check matters MORE on this path than on the ordinary one: it is the only thing
 * proving the unwrapped key belongs to this ciphertext rather than to some other
 * capsule whose wrap was misfiled here.
 *
 * ⚠️ Behaviour of the ordinary path is unchanged — `openCapsule` now calls this
 * immediately after `combine`, with the same key it always computed.
 */
export async function openWithCapsuleKey(
  envelopeId: string,
  envelope: CapsuleCrypto,
  capsuleKey: Uint8Array,
): Promise<OpenResult> {
  // 1. Header MAC — proves the factor list was not downgraded.
  const headerKey = await hkdf(capsuleKey, new Uint8Array(0), utf8(LABEL_HEADER));
  const expectedMac = await hmac(headerKey, canonicalHeader(envelope.version, envelopeId, envelope.factors, envelope.layers));
  if (!timingSafeEqual(expectedMac, envelope.headerMac)) {
    throw new EnvelopeIntegrityError('This capsule has been altered since it was sealed (header check failed).');
  }

  // 2. Key commitment — proves exactly one key opens this ciphertext.
  const expectedCommit = await hkdf(capsuleKey, new Uint8Array(0), utf8(LABEL_COMMIT));
  if (!timingSafeEqual(expectedCommit, envelope.commit)) {
    throw new EnvelopeIntegrityError('This capsule did not unlock to the content it was sealed with.');
  }

  // 3. The content itself.
  const iv = envelope.ciphertext.slice(0, IV_BYTES);
  const body = envelope.ciphertext.slice(IV_BYTES);
  const messageKey = await hkdf(capsuleKey, new Uint8Array(0), utf8(LABEL_MESSAGE));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    await aesKey(messageKey, ['decrypt']),
    body as BufferSource,
  );
  return { plaintext: new TextDecoder().decode(plain), capsuleKey };
}

/**
 * Attachment key for a capsule. Derived from `K_c`, so re-protecting a capsule
 * never touches attachment bytes — only the small blob that guards `K_c`.
 */
export async function attachmentKey(capsuleKey: Uint8Array, attachmentId: string): Promise<Uint8Array> {
  return hkdf(capsuleKey, new Uint8Array(0), utf8(LABEL_ATTACHMENT + attachmentId));
}

const KEY_REF_BYTES = 16;

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/**
 * Wrap a per-file AES key under the capsule key, closing the attachment half of
 * the two-factor envelope.
 *
 * ⚠️ THIS IS THE POINT OF THE WHOLE CHANGE. Attachments used to have their AES
 * key IBE-encrypted under the `encryptionId` alone, so a claimable capsule's
 * MESSAGE was guarded by `time` + `link` while its FILES were guarded by `time`
 * only — and the protection badge said two factors for both. Wrapping under
 * `K_c` means an attachment needs exactly what the message needs.
 *
 * ⚠️ THE KEY REF IS RANDOM AND CARRIED IN THE BLOB, NOT THE ATTACHMENT ID.
 * `attachmentKey` wants an id for domain separation, and the id does not exist
 * yet: the canister assigns it in `finalizeAttachmentUpload`, which runs AFTER
 * the bytes are encrypted. Keying on the id was therefore impossible in the
 * order the upload actually happens — the same reason `envelopeId` is not
 * `capsule.id`. A random 16-byte ref gives the same separation and is known at
 * encrypt time.
 *
 * ⚠️ THE BLOB IS SELF-CONTAINED. Magic, ref and IV all travel inside
 * `encryptedAesKey`, which the canister stores and never reads, so nothing here
 * needs a schema change and a legacy attachment is told apart by its bytes
 * rather than by a field somebody has to remember to set.
 */
export async function wrapAttachmentKey(
  capsuleKey: Uint8Array,
  aesKeyBytes: Uint8Array,
): Promise<Uint8Array> {
  if (aesKeyBytes.length !== KEY_BYTES) {
    throw new Error(`An attachment key must be ${KEY_BYTES} bytes; got ${aesKeyBytes.length}.`);
  }
  const keyRef = crypto.getRandomValues(new Uint8Array(KEY_REF_BYTES));
  const wrapIv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const wrapKey = await attachmentKey(capsuleKey, hex(keyRef));
  const wrapped = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: wrapIv as BufferSource },
      await aesKey(wrapKey, ['encrypt']),
      aesKeyBytes as BufferSource,
    ),
  );
  const out = concat([ATTACHMENT_KEY_V2_MAGIC, keyRef, wrapIv, wrapped]);
  // A length the reader checks is only a guard if the writer cannot violate it.
  if (out.length !== ATTACHMENT_KEY_V2_BYTES) {
    throw new Error(`Wrapped attachment key is ${out.length} bytes; expected ${ATTACHMENT_KEY_V2_BYTES}.`);
  }
  return out;
}

/**
 * Recover a per-file AES key from an envelope-wrapped blob.
 *
 * ⚠️ REFUSES A BLOB THAT IS NOT ENVELOPE-WRAPPED rather than attempting it.
 * Falling through to a best-effort unwrap would turn "this is a legacy
 * attachment, use the IBE path" into an AES-GCM authentication failure, which
 * reads to the user as a corrupt file. Two different problems, two messages.
 */
export async function unwrapAttachmentKey(
  capsuleKey: Uint8Array,
  blob: Uint8Array,
): Promise<Uint8Array> {
  if (!isEnvelopeWrappedAttachmentKey(blob)) {
    throw new Error('This attachment key is not envelope-wrapped; use the legacy IBE path.');
  }
  const keyRef = blob.slice(5, 5 + KEY_REF_BYTES);
  const wrapIv = blob.slice(5 + KEY_REF_BYTES, 5 + KEY_REF_BYTES + IV_BYTES);
  const wrapped = blob.slice(5 + KEY_REF_BYTES + IV_BYTES);
  const wrapKey = await attachmentKey(capsuleKey, hex(keyRef));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: wrapIv as BufferSource },
    await aesKey(wrapKey, ['decrypt']),
    wrapped as BufferSource,
  );
  return new Uint8Array(plain);
}
