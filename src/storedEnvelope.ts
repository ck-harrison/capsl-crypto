/**
 * The capsule envelope as the capsl server stores it (D-087): `CapsuleCrypto`
 * with its bytes as base64, and the binding of capsl's `release` share.
 *
 * 🔴 **ONE HOME, TWO SIDES.** The browser writes these (`serverCapsule.ts`) and
 * the server checks them (`server/src/envelope.ts` re-exports this file), so a
 * change here changes both at once. Imports nothing but a type, so the Worker
 * can import it without pulling any browser crypto in.
 */
import type { CapsuleCrypto } from './types';

/** Mirrors `CapsuleCrypto` in frontend/src/backend.ts, with bytes as base64. */
export interface StoredEnvelope {
  version: number;
  factors: { kind: string; params: string }[];
  layers: unknown[];
  headerMac: string;
  ciphertext: string;
  commit: string;
  ext: unknown[];
}

/** The `release` factor's binding, so the header MAC covers which capsule capsl's share is for. */
export function releaseBinding(capsuleId: string): Uint8Array {
  return new TextEncoder().encode(`release:${capsuleId}`);
}

export const b64 = (u: Uint8Array) => {
  let s = '';
  // Chunked: spreading a large array into one call overflows the stack.
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(s);
};
export const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function toStored(e: CapsuleCrypto): StoredEnvelope {
  return {
    version: e.version,
    factors: e.factors.map((f) => ({ kind: f.kind, params: b64(f.params) })),
    layers: [], headerMac: b64(e.headerMac), ciphertext: b64(e.ciphertext), commit: b64(e.commit), ext: [],
  };
}

export function fromStored(s: StoredEnvelope): CapsuleCrypto {
  return {
    version: s.version,
    factors: s.factors.map((f) => ({ kind: f.kind, params: unb64(f.params) })),
    layers: [], headerMac: unb64(s.headerMac), ciphertext: unb64(s.ciphertext), commit: unb64(s.commit),
    timeIdentity: undefined, ext: [],
  };
}
