/**
 * The `release` factor's server side (D-087, docs/OFF-ICP-PLAN.md §2-3; D-088).
 *
 * Each capsule's share is wrapped under RELEASE_MASTER_KEY, a Worker secret that
 * is never stored in D1. The wrap's associated data binds the capsule id, the
 * unlock time, the policy, both parties and the password verifier, so somebody
 * who can WRITE the database still cannot make a share come out early, to
 * someone else, or for a password of their choosing: an edited row no longer
 * unwraps.
 */

export type ReleasePolicy = 'public' | 'parties';

export interface ReleaseRow {
  capsule_id: string;
  owner_id: string;
  /** The recipient's user id, once known. */
  recipient_id: string | null;
  /** A recipient addressed by email before they have an account (verified email must match). */
  recipient_email: string | null;
  policy: ReleasePolicy;
  /** 0 for a password capsule, which has no time lock (D-088). */
  unlock_ms: number;
  /** PBKDF2 verifier from `password.ts`, or null when the capsule has no password. */
  password_verifier: string | null;
}

/** Who is asking. `email` only when the sign-in provider verified it. */
export interface Caller {
  id: string;
  verifiedEmail: string | null;
}

const enc = new TextEncoder();
const IV_BYTES = 12;

function decodeMasterKey(b64: string | undefined): Uint8Array {
  if (!b64) throw new Error('RELEASE_MASTER_KEY is not set.');
  const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error(`RELEASE_MASTER_KEY must be 32 bytes; it is ${raw.length}.`);
  return raw;
}

async function wrapKey(masterB64: string | undefined): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', decodeMasterKey(masterB64) as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('capsl/release/wrap/v1') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Everything a row's share is bound to. Changing any of it breaks the unwrap. */
export function boundData(row: ReleaseRow): Uint8Array {
  return enc.encode(JSON.stringify([
    'capsl/release/v2', row.capsule_id, row.owner_id, row.recipient_id, row.recipient_email,
    row.policy, row.unlock_ms, row.password_verifier,
  ]));
}

export async function wrapShare(masterB64: string | undefined, row: ReleaseRow, share: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: boundData(row) as BufferSource }, await wrapKey(masterB64), share as BufferSource,
  ));
  const out = new Uint8Array(IV_BYTES + ct.length);
  out.set(iv); out.set(ct, IV_BYTES);
  return out;
}

export async function unwrapShare(masterB64: string | undefined, row: ReleaseRow, wrapped: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: wrapped.slice(0, IV_BYTES) as BufferSource, additionalData: boundData(row) as BufferSource },
    await wrapKey(masterB64),
    wrapped.slice(IV_BYTES) as BufferSource,
  ));
}

/**
 * Re-bind a share to a new recipient (a claim-link capsule, at claim). Only the
 * server can do it, because only the server holds the master key, and only
 * while no recipient is set.
 */
export async function rebindRecipient(
  masterB64: string | undefined, row: ReleaseRow, wrapped: Uint8Array, recipientId: string,
): Promise<{ row: ReleaseRow; wrapped: Uint8Array }> {
  if (row.recipient_id !== null || row.recipient_email !== null) throw new Error('This capsule already has a recipient.');
  const share = await unwrapShare(masterB64, row, wrapped);
  const next = { ...row, recipient_id: recipientId };
  return { row: next, wrapped: await wrapShare(masterB64, next, share) };
}

export type ReleaseDecision =
  | { ok: true }
  | { ok: false; status: 401 | 403 | 425; reason: string };

/**
 * Who may have the share, and when. Pure, so every branch is testable. The
 * caller verifies the password (slow) and passes the result in.
 *
 * There is deliberately NO admin or support override: no sign-in method, staff
 * member or admin can take a share outside its policy (OFF-ICP-PLAN §3.2).
 */
export function mayRelease(row: ReleaseRow, caller: Caller | null, nowMs: number, passwordMatched = false): ReleaseDecision {
  if (nowMs < row.unlock_ms) return { ok: false, status: 425, reason: 'Still locked.' };
  if (row.policy === 'parties') {
    const isParty = caller !== null && (
      caller.id === row.owner_id
      || caller.id === row.recipient_id
      || (row.recipient_email !== null && caller.verifiedEmail === row.recipient_email)
    );
    if (!isParty) {
      return caller === null
        ? { ok: false, status: 401, reason: 'Sign in to open this capsule.' }
        : { ok: false, status: 403, reason: 'Only the sender and the recipient can open this capsule.' };
    }
  }
  if (row.password_verifier !== null && !passwordMatched) return { ok: false, status: 403, reason: 'Wrong password.' };
  return { ok: true };
}
