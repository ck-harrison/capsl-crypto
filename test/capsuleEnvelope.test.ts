import { describe, it, expect } from 'vitest';
import {
  sealCapsule,
  openCapsule,
  linkSealer,
  linkOpener,
  timeSealer,
  timeOpener,
  generateLinkSecret,
  attachmentKey,
  wrapAttachmentKey,
  unwrapAttachmentKey,
  timingSafeEqual,
  envelopeIdFor,
  EnvelopeIntegrityError,
} from '../src/capsuleEnvelope';
import {
  isEnvelopeWrappedAttachmentKey,
  ATTACHMENT_KEY_V2_BYTES,
} from '../src/capsuleFormat';

// A stand-in for the vetKD `time` factor. Real wrapping is IBE to an identity
// the network will not release early; for tests all that matters is that the
// share round-trips and that the stored ciphertext is opaque to the combiner.
function fakeTimeFactor() {
  const vault = new Map<string, Uint8Array>();
  const publicKey = new Uint8Array([0xaa, 0xbb, 0xcc]);
  let n = 0;
  const sealer = timeSealer(async (share) => {
    const id = `ct-${n++}`;
    vault.set(id, share);
    return { ciphertext: new TextEncoder().encode(id), publicKey };
  });
  const opener = timeOpener(async (ciphertext) => {
    const id = new TextDecoder().decode(ciphertext);
    const share = vault.get(id);
    if (!share) throw new Error('release refused');
    return share;
  });
  return { sealer, opener };
}

// The envelope's domain separator. In production this is the hex of the
// capsule's vetKD identity, NOT `capsule.id` — see capsuleEnvelope.ts's header.
const ENVELOPE_ID = 'a1b2c3';
const SECRET = 'the pigeons have landed';

describe('capsule envelope', () => {
  it('round-trips with a single time factor', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    await expect(openCapsule(ENVELOPE_ID, env, [opener])).resolves.toMatchObject({ plaintext: SECRET });
  });

  it('round-trips with time AND link', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);
    expect(env.factors.map((f) => f.kind)).toEqual(['time', 'link']);
    await expect(openCapsule(ENVELOPE_ID, env, [opener, linkOpener(link)])).resolves.toMatchObject({ plaintext: SECRET });
  });

  it('never stores the link secret — a link factor carries no ciphertext', async () => {
    const link = generateLinkSecret();
    const { sealer } = fakeTimeFactor();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);
    const linkFactor = env.factors.find((f) => f.kind === 'link')!;
    // params is two length-prefixed empty fields: 8 bytes of zeroes, nothing else.
    expect(linkFactor.params.length).toBe(8);
    // The secret must appear NOWHERE in the stored envelope.
    const blob = new Uint8Array([...env.ciphertext, ...env.commit, ...env.headerMac, ...linkFactor.params]);
    expect(indexOfSub(blob, link)).toBe(-1);
  });

  // ── This is the security property the whole design exists for ────────────
  it('BREAKING THE TIME FACTOR ALONE DOES NOT OPEN THE CAPSULE', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);

    // An attacker who fully breaks vetKD recovers the time share. Model that
    // as having the real time opener, but the wrong link secret.
    const wrongLink = generateLinkSecret();
    await expect(openCapsule(ENVELOPE_ID, env, [opener, linkOpener(wrongLink)]))
      .rejects.toThrow(EnvelopeIntegrityError);
  });

  // A SECOND, independent guard on the same property. Mutation testing showed
  // the headline test above was the only thing holding it: a combiner that
  // ignored every share after the first killed that test and nothing else,
  // because the header MAC caught the downgrade case on its own. One assertion
  // on the design's central security property is too thin, so this asserts it
  // directly at the key level rather than through a decrypt failure.
  it('every factor changes the capsule key, not just the first', async () => {
    const { sealer } = fakeTimeFactor();
    const linkA = generateLinkSecret();
    const linkB = generateLinkSecret();

    // Same time factor instance, so its share generation is the only variable
    // we are NOT holding constant; run each seal twice and compare across the
    // link secret instead.
    const a1 = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(linkA)]);
    const a2 = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(linkA)]);
    const b = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(linkB)]);

    // Distinct seals always differ (fresh time share each), which is the
    // baseline; the point is that the LINK share reaches the key at all.
    expect(timingSafeEqual(a1.capsuleKey, a2.capsuleKey)).toBe(false);
    expect(timingSafeEqual(a1.capsuleKey, b.capsuleKey)).toBe(false);

    // The decisive check: hold the time share fixed and vary ONLY the link.
    const fixedTime = timeSealer(async () => ({
      ciphertext: new Uint8Array([1, 2, 3]),
      publicKey: new Uint8Array([4, 5]),
    }));
    // timeSealer generates its share internally, so pin it by using a sealer
    // that returns a constant share.
    const constantTime = { kind: 'time', seal: async () => ({
      share: new Uint8Array(32).fill(7),
      ciphertext: new Uint8Array([1, 2, 3]),
      publicKey: new Uint8Array([4, 5]),
    }) };
    void fixedTime;
    const c1 = await sealCapsule(ENVELOPE_ID, SECRET, [constantTime, linkSealer(linkA)]);
    const c2 = await sealCapsule(ENVELOPE_ID, SECRET, [constantTime, linkSealer(linkA)]);
    const c3 = await sealCapsule(ENVELOPE_ID, SECRET, [constantTime, linkSealer(linkB)]);
    // Identical inputs -> identical key (proves the fixture really is fixed).
    expect(timingSafeEqual(c1.capsuleKey, c2.capsuleKey)).toBe(true);
    // Only the link differs -> the key MUST differ.
    expect(timingSafeEqual(c1.capsuleKey, c3.capsuleKey)).toBe(false);
  });

  it('the link alone does not open it either', async () => {
    const { sealer } = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);
    const brokenTime = timeOpener(async () => new Uint8Array(32)); // wrong share
    await expect(openCapsule(ENVELOPE_ID, env, [brokenTime, linkOpener(link)]))
      .rejects.toThrow(EnvelopeIntegrityError);
  });

  it('rejects a downgraded factor list', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);
    // Strip the link factor, as an attacker editing stored metadata would.
    const downgraded = { ...env, factors: [env.factors[0]] };
    await expect(openCapsule(ENVELOPE_ID, downgraded, [opener])).rejects.toThrow(EnvelopeIntegrityError);
  });

  it('rejects a tampered header even when the shares are correct', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    const tampered = { ...env, headerMac: new Uint8Array(env.headerMac.length) };
    await expect(openCapsule(ENVELOPE_ID, tampered, [opener])).rejects.toThrow(/altered since it was sealed/);
  });

  it('rejects a tampered commitment', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    const tampered = { ...env, commit: new Uint8Array(env.commit.length) };
    await expect(openCapsule(ENVELOPE_ID, tampered, [opener])).rejects.toThrow(EnvelopeIntegrityError);
  });

  it('is bound to its capsule id — an envelope cannot be replayed into another capsule', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    await expect(openCapsule('CAP99', env, [opener])).rejects.toThrow(EnvelopeIntegrityError);
  });

  it('refuses to seal a capsule with no factors', async () => {
    await expect(sealCapsule(ENVELOPE_ID, SECRET, [])).rejects.toThrow(/at least one factor/);
  });

  it('rejects a factor/opener kind mismatch rather than silently misreading', async () => {
    const { sealer } = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);
    // Openers supplied in the wrong order.
    await expect(openCapsule(ENVELOPE_ID, env, [linkOpener(link), timeOpener(async () => new Uint8Array(32))]))
      .rejects.toThrow(/but a .* opener was supplied/);
  });

  it('rejects the wrong number of openers', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);
    await expect(openCapsule(ENVELOPE_ID, env, [opener])).rejects.toThrow(/needs 2 factor/);
  });

  it('produces a different ciphertext every time for identical input', async () => {
    const { sealer } = fakeTimeFactor();
    const a = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    const b = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    expect(indexOfSub(a.crypto.ciphertext, b.crypto.ciphertext)).toBe(-1);
    expect(timingSafeEqual(a.capsuleKey, b.capsuleKey)).toBe(false);
  });

  it('never leaks the plaintext into the stored envelope', async () => {
    const { sealer } = fakeTimeFactor();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    const blob = new Uint8Array([...env.ciphertext, ...env.commit, ...env.headerMac, ...env.factors[0].params]);
    expect(indexOfSub(blob, new TextEncoder().encode(SECRET))).toBe(-1);
  });

  it('derives distinct, stable attachment keys', async () => {
    const { sealer } = fakeTimeFactor();
    const { capsuleKey } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer]);
    const a1 = await attachmentKey(capsuleKey, 'att-1');
    const a1again = await attachmentKey(capsuleKey, 'att-1');
    const a2 = await attachmentKey(capsuleKey, 'att-2');
    expect(timingSafeEqual(a1, a1again)).toBe(true);
    expect(timingSafeEqual(a1, a2)).toBe(false);
    expect(a1.length).toBe(32);
  });

  // The testable half of the §7 "fragment never transmitted" gate. The other
  // half is that nothing puts the secret in a request body, which is a property
  // of the call sites; this asserts the ENVELOPE itself, which is the artifact
  // that actually gets stored on-chain forever.
  it('stores nothing derived from the link secret', async () => {
    const { sealer } = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, SECRET, [sealer, linkSealer(link)]);
    const stored = new Uint8Array([
      ...env.ciphertext, ...env.commit, ...env.headerMac,
      ...env.factors.flatMap((f) => [...f.params]),
    ]);
    expect(indexOfSub(stored, link)).toBe(-1);
    // The link factor's params must be an EMPTY ciphertext and an EMPTY public
    // key (two zero-length prefixes = 8 zero bytes). Anything else means the
    // factor started storing recoverable material, which silently removes the
    // whole post-quantum property while every other test still passes.
    const linkFactor = env.factors.find((f) => f.kind === 'link')!;
    expect(Array.from(linkFactor.params)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it('handles unicode and long messages', async () => {
    const { sealer, opener } = fakeTimeFactor();
    const msg = '🕰️ héllo wörld '.repeat(2000);
    const { crypto: env } = await sealCapsule(ENVELOPE_ID, msg, [sealer]);
    await expect(openCapsule(ENVELOPE_ID, env, [opener])).resolves.toMatchObject({ plaintext: msg });
  });
});

describe('envelopeIdFor', () => {
  it('is lowercase hex, zero-padded, and stable', () => {
    expect(envelopeIdFor(new Uint8Array([0x00, 0x0f, 0xa0, 0xff]))).toBe('000fa0ff');
    const id = new Uint8Array(32).fill(7);
    expect(envelopeIdFor(id)).toBe(envelopeIdFor(id));
    expect(envelopeIdFor(id).length).toBe(64);
  });

  it('separates two capsules whose identities differ by one bit', () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32);
    b[31] = 1;
    expect(envelopeIdFor(a)).not.toBe(envelopeIdFor(b));
  });
});

describe('timingSafeEqual', () => {
  it('compares by value and length', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

/** Index of `needle` in `hay`, or -1. Used to assert secrets are absent. */
function indexOfSub(hay: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0 || needle.length > hay.length) return -1;
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}


// ── Attachment keys under the capsule key (2026-09-07) ──────────────────────
//
// The gap these close: a claimable capsule's MESSAGE was sealed under
// `time` + `link` while its ATTACHMENTS had their AES key IBE-wrapped under the
// `encryptionId` alone, so the files were guarded by one factor and the
// protection badge claimed two for both.
describe('attachment key wrapping', () => {
  const capsuleKey = () => crypto.getRandomValues(new Uint8Array(32));
  const aesKey = () => crypto.getRandomValues(new Uint8Array(32));

  it('round-trips an AES key under the capsule key', async () => {
    const kc = capsuleKey();
    const k = aesKey();
    const blob = await wrapAttachmentKey(kc, k);
    expect(await unwrapAttachmentKey(kc, blob)).toEqual(k);
  });

  it('produces a blob the discriminator recognises, at the declared length', async () => {
    const blob = await wrapAttachmentKey(capsuleKey(), aesKey());
    expect(blob.length).toBe(ATTACHMENT_KEY_V2_BYTES);
    expect(isEnvelopeWrappedAttachmentKey(blob)).toBe(true);
  });

  // The whole point: without K_c the file does not open, which is what makes the
  // attachment two-factor rather than one.
  it('refuses a different capsule key', async () => {
    const blob = await wrapAttachmentKey(capsuleKey(), aesKey());
    await expect(unwrapAttachmentKey(capsuleKey(), blob)).rejects.toThrow();
  });

  it('is randomised, so two wraps of the same key differ', async () => {
    const kc = capsuleKey();
    const k = aesKey();
    const a = await wrapAttachmentKey(kc, k);
    const b = await wrapAttachmentKey(kc, k);
    expect(timingSafeEqual(a, b)).toBe(false);
    // ...and both still open, so the randomness is in the wrap and not a bug.
    expect(await unwrapAttachmentKey(kc, a)).toEqual(k);
    expect(await unwrapAttachmentKey(kc, b)).toEqual(k);
  });

  it('detects tampering anywhere in the blob', async () => {
    const kc = capsuleKey();
    const blob = await wrapAttachmentKey(kc, aesKey());
    // Every region matters: magic, keyRef, IV, ciphertext.
    for (const i of [0, 6, 24, blob.length - 1]) {
      const bad = new Uint8Array(blob);
      bad[i] ^= 0xff;
      await expect(unwrapAttachmentKey(kc, bad)).rejects.toThrow();
    }
  });

  // ⚠️ INVERSE CONTROL. Without this, a discriminator that always answered true
  // would pass every test above, and every LEGACY attachment would then be sent
  // down the envelope path and fail as a corrupt file.
  it('does not claim a legacy or malformed blob is envelope-wrapped', () => {
    expect(isEnvelopeWrappedAttachmentKey(undefined)).toBe(false);
    expect(isEnvelopeWrappedAttachmentKey(null)).toBe(false);
    expect(isEnvelopeWrappedAttachmentKey(new Uint8Array(0))).toBe(false);
    // Right length, wrong magic — the length test alone must not be enough.
    expect(isEnvelopeWrappedAttachmentKey(new Uint8Array(ATTACHMENT_KEY_V2_BYTES))).toBe(false);
    // A realistic legacy IBE serialization is far longer than 81 bytes.
    expect(isEnvelopeWrappedAttachmentKey(crypto.getRandomValues(new Uint8Array(400)))).toBe(false);
  });

  it('refuses to unwrap a blob it does not recognise, rather than trying', async () => {
    // A legacy IBE blob reaching the envelope path must say so, not surface as
    // an AES-GCM authentication failure that reads as a corrupt file.
    await expect(unwrapAttachmentKey(capsuleKey(), crypto.getRandomValues(new Uint8Array(400))))
      .rejects.toThrow(/not envelope-wrapped/);
  });

  it('refuses a key that is not 32 bytes', async () => {
    await expect(wrapAttachmentKey(capsuleKey(), new Uint8Array(16))).rejects.toThrow(/32 bytes/);
  });

  // The key actually used per attachment is domain-separated by the random ref
  // inside the blob, so `attachmentKey` is what does the separating.
  it('derives distinct wrap keys per ref and is deterministic per ref', async () => {
    const kc = capsuleKey();
    const a = await attachmentKey(kc, 'ref-a');
    expect(await attachmentKey(kc, 'ref-a')).toEqual(a);
    expect(timingSafeEqual(a, await attachmentKey(kc, 'ref-b'))).toBe(false);
  });

  it('gives openCapsule the same capsule key sealCapsule returned', async () => {
    const time = fakeTimeFactor();
    const link = generateLinkSecret();
    const { crypto: env, capsuleKey: sealedKey } =
      await sealCapsule(ENVELOPE_ID, 'hello', [time.sealer, linkSealer(link)]);
    const { capsuleKey: openedKey } =
      await openCapsule(ENVELOPE_ID, env, [time.opener, linkOpener(link)]);
    // Without this the attachment path would wrap under one key and unwrap with
    // another, and the failure would look like a corrupt file.
    expect(timingSafeEqual(sealedKey, openedKey)).toBe(true);
    const blob = await wrapAttachmentKey(sealedKey, new Uint8Array(32).fill(7));
    expect(await unwrapAttachmentKey(openedKey, blob)).toEqual(new Uint8Array(32).fill(7));
  });
});
