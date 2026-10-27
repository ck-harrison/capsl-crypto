/**
 * Capsule crypto-envelope format gate (QUANTUM-PLAN Phase 1).
 *
 * This module is deliberately TINY and dependency-free so the decrypt call
 * sites can import it statically. `utils/vetkeys.ts` pulls in @dfinity/vetkeys,
 * which every dialog loads lazily via `await import(...)` to keep it out of the
 * main bundle. The format check has to run BEFORE that lazy import, so it
 * cannot live there.
 */

import type { CapsuleCrypto, AttachmentMetadata } from './types';

/**
 * The highest envelope format version this bundle can open.
 *
 * capsl is a PWA, so old bundles stay alive in the wild for a long time. When a
 * future format ships, THIS build will meet capsules it cannot read, and it has
 * to say so in words rather than failing as a crypto error or, worse, rendering
 * an empty body. That behaviour cannot be retrofitted into bundles already
 * deployed, which is why the guard ships before anything writes an envelope.
 *
 * Bump this only when this bundle can genuinely decrypt the new version.
 */
export const SUPPORTED_CRYPTO_VERSION = 1;

/** User-facing copy for the unsupported case. One definition, one wording. */
export const UNSUPPORTED_FORMAT_MESSAGE =
  'This capsule uses a newer capsl format. Please reload the page to update.';

/** Thrown when a capsule's envelope is newer than this bundle understands. */
export class UnsupportedCapsuleFormatError extends Error {
  readonly version: number;
  constructor(version: number) {
    super(UNSUPPORTED_FORMAT_MESSAGE);
    this.name = 'UnsupportedCapsuleFormatError';
    this.version = version;
  }
}

/**
 * True when this bundle cannot open the capsule.
 *
 * `undefined` means a legacy capsule on the encryptedMessage path, which is
 * always supported. A present-but-older version is supported too.
 */
export function isUnsupportedCapsuleFormat(crypto?: CapsuleCrypto): boolean {
  return !!crypto && crypto.version > SUPPORTED_CRYPTO_VERSION;
}

/** Throwing form, for use inside the decrypt helpers' try/catch paths. */
export function assertSupportedCapsuleFormat(crypto?: CapsuleCrypto): void {
  if (isUnsupportedCapsuleFormat(crypto)) {
    throw new UnsupportedCapsuleFormatError(crypto!.version);
  }
}

/**
 * True when this capsule's message lives in the envelope rather than on the
 * legacy `encryptedMessage` field.
 *
 * Lives here rather than in `capsuleEnvelopeIo.ts` so a decrypt site can pick
 * its branch WITHOUT loading @dfinity/vetkeys, which is the same reason the
 * version guard lives here. Requires a factor list and a ciphertext: an
 * envelope with neither is a reserved slot, not a sealed message.
 */
export function hasCapsuleEnvelope(crypto?: CapsuleCrypto): boolean {
  return !!crypto && crypto.factors.length > 0 && crypto.ciphertext.length > 0;
}

/** How each factor kind is described to a person. */
const FACTOR_LABELS: Record<string, string> = {
  time: 'a time lock',
  release: "capsl's share",
  link: 'its link',
  secret: 'a recovery phrase',
  recipient: "the recipient's key",
  group: 'a group of key holders',
};

/**
 * One sentence naming what actually guards this capsule, derived from the stored
 * factor list rather than from the capsule's type.
 *
 * QUANTUM-PLAN §0.2 and the Phase 6 gate both require this to be read off the
 * envelope: a statement hardcoded per capsule type goes quietly false the first
 * time a type's factor set changes, and this is a claim about the user's own
 * data. An unrecognised kind is printed verbatim rather than dropped, so a newer
 * factor never disappears from the sentence.
 */
export function describeCapsuleProtection(crypto?: CapsuleCrypto): string | null {
  if (!hasCapsuleEnvelope(crypto)) return null;
  const parts = crypto!.factors.map((f) => FACTOR_LABELS[f.kind] ?? f.kind);
  if (parts.length === 1) return `Sealed with ${parts[0]}.`;
  return `Sealed with ${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}. All of them are required.`;
}

/**
 * Does this capsule record actually CARRY its contents, or is it the husk the
 * canister hands out for a locked one?
 *
 * `Capsules.sanitizeCapsuleForCaller` strips a locked capsule server-side:
 * `message = ""`, `attachments = []`, `encryptedMessage = null`, `crypto = null`.
 * A record fetched BEFORE the unlock time therefore contains nothing to show —
 * while a wall-clock check like `ViewCapsuleDialog`'s `computeUnlocked` starts
 * saying "unlocked" the instant the deadline passes. Those two together
 * auto-revealed an EMPTY capsule on the Sent tab: the body renders
 * `decryptedMessage ?? message ?? ''`, the decrypt effect bails for want of any
 * ciphertext, and the user got a blank capsule where their message should be.
 * Observed on staging by a human, 2026-08-18.
 *
 * So "unlocked" in the UI must mean **"I am holding the contents"**, not "the
 * clock says so". Any real capsule has ciphertext (everything is encrypted at
 * creation); legacy plaintext capsules have a non-empty message; an
 * attachment-only capsule has attachments.
 */
export function recordHasContent(c: {
    message?: string;
    encryptedMessage?: Uint8Array;
    crypto?: CapsuleCrypto;
    attachments?: unknown[];
} | null | undefined): boolean {
    if (!c) return false;
    if (c.crypto != null) return true;
    if (c.encryptedMessage != null) return true;
    if (c.message !== undefined && c.message !== '') return true;
    return (c.attachments?.length ?? 0) > 0;
}

/** Every field that carries the capsule itself, as opposed to describing it. */
export interface UnlockedContentFields {
    message?: string;
    encryptedMessage?: Uint8Array;
    encryptionId?: Uint8Array;
    crypto?: CapsuleCrypto;
    attachments?: AttachmentMetadata[];
    actualUnlockTimestamp?: bigint;
}

/**
 * Merge the record a successful unlock returned onto the one already on screen,
 * carrying EVERY content-bearing field across.
 *
 * WHY THIS EXISTS, AND WHY IT IS SHARED. Three call sites adopt the result of
 * `unlockCapsuleWithPassword`. Two of them (`ViewCapsuleDialog`, `CapsuleCard`)
 * adopt the whole record and were always correct. `ViewPublicCapsuleDialog`
 * built the revealed record BY HAND instead — copying `isUnlocked`, `message`
 * and `actualUnlockTimestamp` onto the stale locked capsule, and silently
 * dropping `encryptedMessage`, `encryptionId` and `crypto`.
 *
 * That is fatal rather than cosmetic, because every capsule is encrypted at
 * creation, so the server's `message` is the literal placeholder
 * `"[Encrypted]"`. With no ciphertext and no identity on the record, the decrypt
 * effect has nothing to work with and the body renders `[Encrypted]` forever.
 * Reproduced on production 2026-08-20: the correct password unlocked `CAP49`,
 * the shell flipped to `◉ REVEALED`, and the message read `[Encrypted]`. The
 * canister was fine throughout — it returned the full record and the unlock was
 * recorded; only this merge lost it.
 *
 * The hand-written merge almost certainly existed because the state is typed
 * `PublicCapsule` while the result is a `TimeCapsule`, so someone copied the
 * fields that obviously overlapped. This helper is typed on the structural
 * subset the two share, which needs no cast and cannot quietly omit a field.
 *
 * Root-cause shape: "when two places decide the same thing, they must call one
 * function" (root `CLAUDE.md`). This is the third time that rule has been earned
 * on the reveal path.
 */
export function mergeUnlockedContent<T extends UnlockedContentFields>(
    prev: T,
    updated: UnlockedContentFields | null | undefined,
): T {
    if (!updated) return prev;
    const out: T = { ...prev };
    if (updated.message !== undefined) out.message = updated.message;
    if (updated.encryptedMessage !== undefined) out.encryptedMessage = updated.encryptedMessage;
    if (updated.encryptionId !== undefined) out.encryptionId = updated.encryptionId;
    if (updated.crypto !== undefined) out.crypto = updated.crypto;
    if (updated.attachments !== undefined) out.attachments = updated.attachments;
    if (updated.actualUnlockTimestamp !== undefined) out.actualUnlockTimestamp = updated.actualUnlockTimestamp;
    return out;
}

// ── Attachment key wrapping: which scheme guards THIS attachment ────────────

/**
 * Magic prefix on an `encryptedAesKey` blob whose AES key is wrapped under the
 * capsule key `K_c` rather than IBE-encrypted under the `encryptionId`.
 *
 * WHY A MAGIC RATHER THAN A FLAG ON THE RECORD. `attachmentEncryption` is a
 * stable var and `encryptedAesKey` is opaque bytes the canister only stores and
 * never inspects, so a version marker INSIDE the blob needs no schema change
 * and no migration — the same trick the envelope's `params`/`payload` use. A
 * new field on `AttachmentMetadata` would have needed `Migration.mo`, which is
 * exactly the belief that kept this work parked for months (QUANTUM-PLAN §9,
 * corrected 2026-08-20).
 */
export const ATTACHMENT_KEY_V2_MAGIC = Uint8Array.from([0x63, 0x61, 0x32, 0x00, 0x01]);

/** magic(5) + keyRef(16) + wrapIv(12) + AES-GCM(32-byte key) + tag(16). */
export const ATTACHMENT_KEY_V2_BYTES = 5 + 16 + 12 + 32 + 16;

/**
 * True when this wrapped-key blob is envelope-wrapped (two factors) rather than
 * legacy IBE-wrapped (`time` alone).
 *
 * ⚠️ THIS LIVES HERE, NOT IN `vetkeys.ts`, FOR THE SAME REASON
 * `hasCapsuleEnvelope` does: a decrypt site has to know whether it needs the
 * capsule key BEFORE deciding to lazy-import `@dfinity/vetkeys`, and a static
 * import of that module from a hook drags ~80 KB out of its lazy chunk into the
 * main bundle. This module imports nothing but types; keep it that way.
 *
 * ⚠️ LENGTH IS CHECKED AS WELL AS THE MAGIC. A legacy IBE serialization is far
 * longer than 81 bytes, so either test alone would do — but a five-byte prefix
 * is a weak discriminator on its own and this costs nothing.
 */
export function isEnvelopeWrappedAttachmentKey(encryptedAesKey?: Uint8Array | null): boolean {
    if (!encryptedAesKey || encryptedAesKey.length !== ATTACHMENT_KEY_V2_BYTES) return false;
    for (let i = 0; i < ATTACHMENT_KEY_V2_MAGIC.length; i++) {
        if (encryptedAesKey[i] !== ATTACHMENT_KEY_V2_MAGIC[i]) return false;
    }
    return true;
}
