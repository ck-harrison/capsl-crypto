/**
 * Browser side of creating and opening a capsule against the new server
 * (D-087 phase 2, D-088). Browser code: it lives here until the frontend
 * switches in phase 6, and is tested from here against the real Worker.
 *
 * The envelope itself is `frontend/src/utils/capsuleEnvelope.ts`, unchanged.
 * This file only decides WHICH factors a capsule gets (the same rule the server
 * enforces, `expectedKinds`) and moves bytes between the envelope and the API.
 */
import {
  sealCapsule, openCapsule, linkSealer, linkOpener, timeSealer, timeOpener, generateLinkSecret,
  type FactorSealer, type FactorOpener,
} from './capsuleEnvelope';
import type { CapsuleCrypto } from './types';
import { releaseBinding, type StoredEnvelope } from './envelope';

const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

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

/** capsl's share as an envelope factor. Bound to the capsule id, so the header MAC covers it. */
export function releaseFactor(share: Uint8Array, capsuleId: string): FactorSealer & FactorOpener {
  return {
    kind: 'release',
    async seal() { return { share, ciphertext: new Uint8Array(0), publicKey: releaseBinding(capsuleId) }; },
    async open() { return share; },
  };
}

/** How the time lock is made. drand in production; tests may pass a stand-in. */
export interface TimeLock {
  wrap(unlockMs: number): (share: Uint8Array) => Promise<{ ciphertext: Uint8Array; publicKey: Uint8Array }>;
  unwrap(): (ciphertext: Uint8Array, publicKey: Uint8Array) => Promise<Uint8Array>;
}
/**
 * drand, imported only when a time lock is actually made or opened. tlock-js
 * is large and does not load in every runtime (it fails inside the Workers test
 * pool), and a password capsule never needs it.
 */
export const drandTimeLock: TimeLock = {
  wrap: (ms) => async (share) => (await import('./drandTime')).drandWrap(ms)(share),
  unwrap: () => async (ct, pk) => (await import('./drandTime')).drandUnwrap()(ct, pk),
};

/** Calls the API; the caller supplies auth (a cookie in tests, the browser's own in the app). */
export type Api = (path: string, init?: { method?: string; body?: unknown }) => Promise<{ status: number; json: any }>;

export class CapsuleApiError extends Error {
  constructor(readonly status: number, message: string, readonly body?: unknown) { super(message); }
}

async function ok(api: Api, path: string, init?: { method?: string; body?: unknown }) {
  const r = await api(path, init);
  if (r.status < 200 || r.status > 299) throw new CapsuleApiError(r.status, r.json?.error ?? `HTTP ${r.status}`, r.json);
  return r.json;
}

export interface CreateInput {
  title: string;
  description?: string;
  audience: 'public' | 'private' | 'recipient' | 'claim';
  linkRequired: boolean;
  /** Omit for a password capsule (D-088: no time lock). */
  unlockMs?: number;
  password?: string;
  retentionUntilMs: number;
  recipientUsername?: string;
  recipientEmail?: string;
  isAnonymous?: boolean;
  shell?: number;
}

export interface Created {
  capsuleId: string;
  claimToken: string | null;
  /** Only when the link is required. capsl never sees it; losing it loses the capsule. */
  linkSecret: Uint8Array | null;
  capsuleKey: Uint8Array;
}

export async function createCapsule(api: Api, input: CreateInput, message: string, time: TimeLock = drandTimeLock): Promise<Created> {
  const draft = await ok(api, '/v1/capsules', { method: 'POST', body: input });
  const factors: FactorSealer[] = [];
  if (draft.unlockMs !== null) factors.push(timeSealer(time.wrap(draft.unlockMs)));
  factors.push(releaseFactor(unb64(draft.releaseShare), draft.capsuleId));
  const linkSecret = input.linkRequired ? generateLinkSecret() : null;
  if (linkSecret) factors.push(linkSealer(linkSecret));

  const sealed = await sealCapsule(draft.capsuleId, message, factors);
  await ok(api, `/v1/capsules/${draft.capsuleId}/seal`, { method: 'POST', body: { envelope: toStored(sealed.crypto) } });
  return { capsuleId: draft.capsuleId, claimToken: draft.claimToken, linkSecret, capsuleKey: sealed.capsuleKey };
}

export class MissingLinkError extends Error {}

export async function openCapsuleById(
  api: Api, capsuleId: string, opts: { password?: string; linkSecret?: Uint8Array | null; time?: TimeLock } = {},
): Promise<{ plaintext: string; capsuleKey: Uint8Array }> {
  const got = await ok(api, `/v1/capsules/${capsuleId}/open`, {
    method: 'POST', body: opts.password === undefined ? {} : { password: opts.password },
  });
  const envelope = fromStored(got.envelope);
  const share = unb64(got.releaseShare);
  const openers: FactorOpener[] = envelope.factors.map((f) => {
    if (f.kind === 'time') return timeOpener((opts.time ?? drandTimeLock).unwrap());
    if (f.kind === 'release') return releaseFactor(share, capsuleId);
    if (f.kind === 'link') {
      // A missing link is not a decryption failure (root CLAUDE.md): say so.
      if (!opts.linkSecret) throw new MissingLinkError('This capsule needs its link to open.');
      return linkOpener(opts.linkSecret);
    }
    throw new Error(`Unknown factor "${f.kind}".`);
  });
  return openCapsule(capsuleId, envelope, openers);
}
