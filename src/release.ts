/**
 * The `release` factor's server side (D-087, docs/OFF-ICP-PLAN.md §2-3).
 *
 * Each capsule's share is wrapped under RELEASE_MASTER_KEY, a Worker secret that
 * is never stored in D1. The wrap's associated data binds the capsule id, the
 * unlock time, the policy and both parties, so somebody who can WRITE the
 * database still cannot make a share come out early or to someone else: an
 * edited row no longer unwraps.
 */

export type ReleasePolicy = 'public' | 'parties';

export interface ReleaseRow {
  capsule_id: string;
  owner_id: string;
  recipient_id: string | null;
  policy: ReleasePolicy;
  unlock_ms: number;
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
    'capsl/release/v1', row.capsule_id, row.owner_id, row.recipient_id, row.policy, row.unlock_ms,
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

export type ReleaseDecision =
  | { ok: true }
  | { ok: false; status: 403 | 425; reason: string };

/**
 * Who may have the share, and when. Pure, so every branch is testable.
 *
 * There is deliberately NO admin or support override: no sign-in method, staff
 * member or admin can take a share outside its policy (OFF-ICP-PLAN §3.2).
 */
export function mayRelease(row: ReleaseRow, callerId: string | null, nowMs: number): ReleaseDecision {
  if (nowMs < row.unlock_ms) return { ok: false, status: 425, reason: 'Still locked.' };
  if (row.policy === 'public') return { ok: true };
  if (callerId !== null && (callerId === row.owner_id || callerId === row.recipient_id)) return { ok: true };
  return { ok: false, status: 403, reason: 'Only the sender and the recipient can open this capsule.' };
}
