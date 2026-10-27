/**
 * The stored capsule envelope (D-087 phase 2): its JSON form, and the checks
 * the server runs before it accepts a sealed capsule.
 *
 * The server cannot open an envelope (it never has every share) and does not
 * try. What it CAN check is that the envelope is built the way the capsule's
 * rules say: the right factors in the right order, the time factor bound to
 * the round for this capsule's date, and capsl's share bound to this capsule.
 * Anything else is refused, so a buggy or hostile client cannot seal a
 * capsule with a weaker lock than the screen promised.
 *
 * The header MAC (checked when the capsule is opened) stops the factor list
 * being edited after sealing; this check stops it being wrong from the start.
 */
import { parseDrandBinding, roundForUnlockMs } from './drandRound';
import { releaseBinding, type StoredEnvelope } from './storedEnvelope';

// The stored form and the release binding have ONE home, shared with the
// browser that writes them.
export { releaseBinding, type StoredEnvelope } from './storedEnvelope';

export const ENVELOPE_VERSION = 1;
/** Ciphertext bytes. A 50,000-character message is at most 200 KB of UTF-8 plus the tag. */
export const MAX_CIPHERTEXT_BYTES = 200_100;

const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** `params` is [u32 len][ciphertext][u32 len][publicKey], as written by `capsuleEnvelope.ts`. */
export function splitParams(params: Uint8Array): { ciphertext: Uint8Array; publicKey: Uint8Array } | null {
  if (params.length < 8) return null;
  const view = new DataView(params.buffer, params.byteOffset, params.byteLength);
  const ctLen = view.getUint32(0, false);
  if (8 + ctLen > params.length) return null;
  const pkLen = view.getUint32(4 + ctLen, false);
  if (8 + ctLen + pkLen !== params.length) return null;
  return { ciphertext: params.slice(4, 4 + ctLen), publicKey: params.slice(8 + ctLen) };
}

export interface SealRules {
  capsuleId: string;
  unlockMode: 'date' | 'password';
  unlockMs: number;
  linkRequired: boolean;
}

/** The factor kinds, in order, that a capsule with these rules must carry. */
export function expectedKinds(r: Pick<SealRules, 'unlockMode' | 'linkRequired'>): string[] {
  return [...(r.unlockMode === 'date' ? ['time'] : []), 'release', ...(r.linkRequired ? ['link'] : [])];
}

const isB64 = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(v);

/** Returns null when the envelope is acceptable, else the reason it is refused. */
export function checkEnvelope(raw: unknown, r: SealRules): string | null {
  if (typeof raw !== 'object' || raw === null) return 'The envelope is missing.';
  const e = raw as Partial<StoredEnvelope>;
  if (e.version !== ENVELOPE_VERSION) return `Envelope version must be ${ENVELOPE_VERSION}.`;
  if (!Array.isArray(e.factors) || !Array.isArray(e.layers) || !Array.isArray(e.ext)) return 'The envelope is malformed.';
  if (e.layers.length || e.ext.length) return 'This envelope uses features the server does not accept yet.';
  if (![e.headerMac, e.ciphertext, e.commit].every(isB64)) return 'The envelope is malformed.';
  if (unb64(e.headerMac!).length !== 32 || unb64(e.commit!).length !== 32) return 'The envelope is malformed.';
  const ct = unb64(e.ciphertext!);
  if (ct.length < 12 + 16) return 'The envelope has no ciphertext.';
  if (ct.length > MAX_CIPHERTEXT_BYTES) return 'The message is too long.';

  const want = expectedKinds(r);
  const got = e.factors.map((f) => (f && typeof f.kind === 'string' ? f.kind : '?'));
  if (got.join('|') !== want.join('|')) return `This capsule must be sealed with ${want.join(' + ')}; got ${got.join(' + ')}.`;

  for (const f of e.factors) {
    if (!isB64(f.params)) return 'The envelope is malformed.';
    const p = splitParams(unb64(f.params));
    if (!p) return `The ${f.kind} factor is malformed.`;
    if (f.kind === 'time') {
      const round = parseDrandBinding(p.publicKey);
      if (round === null) return 'The time lock is not bound to drand quicknet.';
      if (round !== roundForUnlockMs(r.unlockMs)) return 'The time lock is bound to the wrong date.';
      if (p.ciphertext.length === 0) return 'The time lock has no ciphertext.';
    } else if (f.kind === 'release') {
      const want = releaseBinding(r.capsuleId);
      const same = p.publicKey.length === want.length && p.publicKey.every((b, i) => b === want[i]);
      if (!same) return "capsl's share is bound to a different capsule.";
      if (p.ciphertext.length) return "capsl's share must not be stored in the envelope.";
    } else if (f.kind === 'link') {
      if (p.ciphertext.length || p.publicKey.length) return 'The link factor must not store anything.';
    }
  }
  return null;
}
