/**
 * Browser side of creating and opening a capsule against the capsl server
 * (D-087, D-088). Moved here from `server/src/client/capsuleClient.ts` in
 * phase 6; the server's tests import THIS file, so there is one implementation.
 *
 * The envelope itself is `capsuleEnvelope.ts`, unchanged. This file only
 * decides WHICH factors a capsule gets (the same rule the server enforces,
 * `expectedKinds`) and moves bytes between the envelope and the API.
 *
 * Creating: POST /v1/capsules makes a draft and hands back capsl's share; the
 * browser seals locally with time (drand) + release (+ link); each file is
 * encrypted under its own key, uploaded, and its key wrapped under the capsule
 * key; `beforeSeal` runs (layout, intro video: both need the draft); then
 * POST /seal stores the envelope and the file list at once.
 *
 * Opening: POST /v1/capsules/:id/open is the one door. It returns the envelope,
 * capsl's share and each file's wrapped key; the time share comes from drand.
 */
import {
  sealCapsule, openCapsule, linkSealer, linkOpener, timeSealer, timeOpener, generateLinkSecret,
  wrapAttachmentKey, unwrapAttachmentKey,
  type FactorSealer, type FactorOpener,
} from './capsuleEnvelope';
import type { CapsuleCrypto } from './types';
import { releaseBinding, toStored, fromStored, b64, unb64, type StoredEnvelope } from './storedEnvelope';

export { toStored, fromStored };

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

/**
 * Calls the API. `raw` sends bytes instead of JSON, with `contentType`. The
 * app's adapter is `apiFromClient` in `frontend/src/server/capsules.ts`; the
 * server's tests pass a cookie-carrying fetch to the Worker.
 */
export type Api = (path: string, init?: { method?: string; body?: unknown; raw?: Uint8Array; contentType?: string }) => Promise<{ status: number; json: any }>;

export class CapsuleApiError extends Error {
  constructor(readonly status: number, message: string, readonly body?: unknown) { super(message); }
}

async function ok(api: Api, path: string, init?: Parameters<Api>[1]) {
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
  /** One of the creator's APPROVED custom shells (`GET /v1/shells`). */
  customShellId?: string;
  giftCredits?: number;
}

export interface Created {
  capsuleId: string;
  claimToken: string | null;
  /** Only when the link is required. capsl never sees it; losing it loses the capsule. */
  linkSecret: Uint8Array | null;
  capsuleKey: Uint8Array;
  /** Each sealed file's storage key, in the order given, with the caller's `ref`. */
  attachments: { ref: string | undefined; key: string }[];
}

/**
 * A file to seal into the capsule, encrypted under the AES key it is given.
 * Parts are at most 64 MiB each, and every part but the last at least 5 MiB
 * (R2's rule; a smaller one fails the upload). In the app that is the v3
 * chunked container (`serverAttachment.ts`), streamed one part at a time so a
 * 5 GB file is never a 5 GB buffer. The key is then wrapped under the capsule
 * key, so the file needs exactly what the message needs to open.
 *
 * Give `encrypt` (all parts at once: small files, tests) or `parts` (streamed,
 * with `sizeBytes` the exact ciphertext total for the reservation).
 */
export interface FileToSeal {
  filename: string;
  contentType: string;
  kind: 'stream' | 'buffered';
  sizeBytes: number;
  encrypt?(aesKey: Uint8Array): Promise<Uint8Array[]>;
  parts?(aesKey: Uint8Array): AsyncIterable<Uint8Array>;
  /** The v3 header, read AFTER the parts are produced; stored beside the file and returned by open. */
  header?(): Uint8Array | null;
  /** The caller's own id for this file (a layout placement refers to it). */
  ref?: string;
}

export interface CreateOptions {
  /** Progress per file: `done` of `total` ciphertext bytes sent. */
  onProgress?(p: { index: number; filename: string; done: number; total: number }): void;
  /** Runs after every file is up and before the seal: the draft exists and is still writable. */
  beforeSeal?(capsuleId: string, uploaded: Created['attachments']): Promise<void>;
}

async function uploadFile(api: Api, capsuleId: string, capsuleKey: Uint8Array, f: FileToSeal, index: number, opts: CreateOptions) {
  const aesKey = crypto.getRandomValues(new Uint8Array(32));
  const eager = f.encrypt ? await f.encrypt(aesKey) : null;
  const total = eager ? eager.reduce((n, p) => n + p.length, 0) : f.sizeBytes;
  const { key } = await ok(api, `/v1/capsules/${capsuleId}/attachments`, { method: 'POST', body: { kind: f.kind, maxBytes: total } });
  const done: { partNumber: number; etag: string }[] = [];
  let sent = 0;
  const source: AsyncIterable<Uint8Array> | Iterable<Uint8Array> = eager ?? f.parts!(aesKey);
  try {
    for await (const part of source) {
      done.push(await ok(api, `/v1/uploads/${key}/parts/${done.length + 1}`, { method: 'PUT', raw: part, contentType: 'application/octet-stream' }));
      sent += part.length;
      opts.onProgress?.({ index, filename: f.filename, done: sent, total });
    }
    if (!done.length) throw new CapsuleApiError(400, `${f.filename} is empty.`);
    await ok(api, `/v1/uploads/${key}/complete`, { method: 'POST', body: done });
  } catch (e) {
    // The draft keeps nothing half-written: a stray multipart costs storage, so abort it.
    await api(`/v1/uploads/${key}/abort`, { method: 'POST' }).catch(() => undefined);
    throw e;
  }
  const header = f.header?.() ?? null;
  return {
    key, filename: f.filename, contentType: f.contentType,
    wrappedKey: b64(await wrapAttachmentKey(capsuleKey, aesKey)),
    ...(header ? { header: b64(header) } : {}),
  };
}

export async function createCapsule(
  api: Api, input: CreateInput, message: string, time: TimeLock = drandTimeLock, filesToSeal: FileToSeal[] = [],
  opts: CreateOptions = {},
): Promise<Created> {
  const draft = await ok(api, '/v1/capsules', { method: 'POST', body: input });
  const factors: FactorSealer[] = [];
  if (draft.unlockMs !== null) factors.push(timeSealer(time.wrap(draft.unlockMs)));
  factors.push(releaseFactor(unb64(draft.releaseShare), draft.capsuleId));
  const linkSecret = input.linkRequired ? generateLinkSecret() : null;
  if (linkSecret) factors.push(linkSealer(linkSecret));

  // Seal first (locally), because each file's key is wrapped under the capsule
  // key the seal produces; then upload; then hand the server both at once.
  const sealed = await sealCapsule(draft.capsuleId, message, factors);
  const attachments: Awaited<ReturnType<typeof uploadFile>>[] = [];
  for (let i = 0; i < filesToSeal.length; i++) attachments.push(await uploadFile(api, draft.capsuleId, sealed.capsuleKey, filesToSeal[i], i, opts));
  const uploaded = attachments.map((a, i) => ({ ref: filesToSeal[i].ref, key: a.key }));
  await opts.beforeSeal?.(draft.capsuleId, uploaded);
  await ok(api, `/v1/capsules/${draft.capsuleId}/seal`, { method: 'POST', body: { envelope: toStored(sealed.crypto), attachments } });
  return { capsuleId: draft.capsuleId, claimToken: draft.claimToken, linkSecret, capsuleKey: sealed.capsuleKey, attachments: uploaded };
}

/** A file as `open` describes it, before its key is unwrapped. */
export interface FetchedAttachment {
  key: string; filename: string; contentType: string; sizeBytes: number; kind: 'stream' | 'buffered';
  wrappedKey: string;
  /** The v3 header (base64), when the file was sealed with one. */
  header?: string | null;
}

export interface OpenedAttachment extends Omit<FetchedAttachment, 'wrappedKey'> {
  /** The file's AES key, unwrapped under the capsule key. Decrypt the bytes from `/v1/files/:key` with it. */
  aesKey: Uint8Array;
}

/**
 * The missing `link` factor. A missing link is not a decryption failure (root
 * CLAUDE.md): say so. Named `MissingFactorError` with `kind: 'link'`, the shape
 * the capsule dialogs already test for by name.
 */
export class MissingLinkError extends Error {
  readonly kind = 'link';
  constructor(message = 'This capsule can only be opened with its link, and that key is not on this device. Use the original link, or paste it below.') {
    super(message);
    this.name = 'MissingFactorError';
  }
}

/** What the one door hands back, before anything is combined. */
export interface Fetched {
  envelope: CapsuleCrypto;
  releaseShare: Uint8Array;
  attachments: FetchedAttachment[];
  layout: string | null;
  giftCredited: number;
}

/** POST /open. Rate-limited and side-effecting on the server (read receipts, gifts): call it once per open. */
export async function fetchOpen(api: Api, capsuleId: string, password?: string): Promise<Fetched> {
  const got = await ok(api, `/v1/capsules/${capsuleId}/open`, {
    method: 'POST', body: password === undefined ? {} : { password },
  });
  return {
    envelope: fromStored(got.envelope as StoredEnvelope),
    releaseShare: unb64(got.releaseShare),
    attachments: (got.attachments ?? []) as FetchedAttachment[],
    layout: got.layout ?? null,
    giftCredited: got.giftCredited ?? 0,
  };
}

/** Combine what `fetchOpen` returned with drand and the link. Makes no request to capsl. */
export async function openFetched(
  capsuleId: string, got: Pick<Fetched, 'envelope' | 'releaseShare' | 'attachments'>,
  opts: { linkSecret?: Uint8Array | null; time?: TimeLock } = {},
): Promise<{ plaintext: string; capsuleKey: Uint8Array; attachments: OpenedAttachment[] }> {
  const openers: FactorOpener[] = got.envelope.factors.map((f) => {
    if (f.kind === 'time') return timeOpener((opts.time ?? drandTimeLock).unwrap());
    if (f.kind === 'release') return releaseFactor(got.releaseShare, capsuleId);
    if (f.kind === 'link') {
      if (!opts.linkSecret) throw new MissingLinkError();
      return linkOpener(opts.linkSecret);
    }
    throw new Error(`Unknown factor "${f.kind}".`);
  });
  const opened = await openCapsule(capsuleId, got.envelope, openers);
  const attachments: OpenedAttachment[] = [];
  for (const a of got.attachments) {
    const { wrappedKey, ...rest } = a;
    attachments.push({ ...rest, aesKey: await unwrapAttachmentKey(opened.capsuleKey, unb64(wrappedKey)) });
  }
  return { ...opened, attachments };
}

export async function openCapsuleById(
  api: Api, capsuleId: string, opts: { password?: string; linkSecret?: Uint8Array | null; time?: TimeLock } = {},
): Promise<{ plaintext: string; capsuleKey: Uint8Array; attachments: OpenedAttachment[] }> {
  return openFetched(capsuleId, await fetchOpen(api, capsuleId, opts.password), opts);
}
