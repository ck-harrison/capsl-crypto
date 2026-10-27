import { describe, expect, it } from 'vitest';
import { mayRelease, rebindRecipient, unwrapShare, wrapShare, type Caller, type ReleaseRow } from '../src/release';
import { ITERATIONS, CLOUDFLARE_PBKDF2_MAX, hashPassword, verifyPassword } from '../src/password';

describe('password verifiers', () => {
  it('SHOULD FAIL in production if raised: the count stays within what real Cloudflare accepts', () => {
    // The local runtime accepts any count, so only this assertion stands between
    // a higher number and every password capsule failing on staging.
    expect(ITERATIONS).toBeLessThanOrEqual(CLOUDFLARE_PBKDF2_MAX);
  });
  it('accepts the right password and refuses a wrong one or a malformed verifier', async () => {
    const v = await hashPassword('correct horse');
    expect(v).toMatch(new RegExp(`^pbkdf2-sha256:${ITERATIONS}:`));
    expect(await verifyPassword('correct horse', v)).toBe(true);
    expect(await verifyPassword('correct hors', v)).toBe(false);
    expect(await verifyPassword('correct horse', 'stretched3:1:a:b')).toBe(false);
  });
});

const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const otherKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const row: ReleaseRow = {
  capsule_id: 'c1', owner_id: 'alice', recipient_id: 'bob', recipient_email: null,
  policy: 'parties', unlock_ms: 2_000, password_verifier: null,
};
const share = crypto.getRandomValues(new Uint8Array(32));
const who = (id: string, verifiedEmail: string | null = null): Caller => ({ id, verifiedEmail });

describe('release share wrapping', () => {
  it('round-trips under the master key', async () => {
    expect(await unwrapShare(key, row, await wrapShare(key, row, share))).toEqual(share);
  });

  it('SHOULD FAIL: a database edit that moves the unlock time earlier breaks the unwrap', async () => {
    const wrapped = await wrapShare(key, row, share);
    await expect(unwrapShare(key, { ...row, unlock_ms: 1 }, wrapped)).rejects.toThrow();
  });

  it('SHOULD FAIL: re-pointing the recipient, the email, the policy or the password breaks the unwrap', async () => {
    const wrapped = await wrapShare(key, row, share);
    await expect(unwrapShare(key, { ...row, recipient_id: 'mallory' }, wrapped)).rejects.toThrow();
    await expect(unwrapShare(key, { ...row, recipient_email: 'm@example.com' }, wrapped)).rejects.toThrow();
    await expect(unwrapShare(key, { ...row, policy: 'public' }, wrapped)).rejects.toThrow();
    await expect(unwrapShare(key, { ...row, password_verifier: 'pbkdf2-sha256:1:AA==:AA==' }, wrapped)).rejects.toThrow();
  });

  it('SHOULD FAIL: the database alone, without the master key, opens nothing', async () => {
    const wrapped = await wrapShare(key, row, share);
    await expect(unwrapShare(otherKey, row, wrapped)).rejects.toThrow();
    await expect(unwrapShare(undefined, row, wrapped)).rejects.toThrow('RELEASE_MASTER_KEY is not set.');
  });

  it('a claim re-binds an unaddressed share to the claimant, and only once', async () => {
    const open = { ...row, recipient_id: null };
    const wrapped = await wrapShare(key, open, share);
    const next = await rebindRecipient(key, open, wrapped, 'carol');
    expect(next.row.recipient_id).toBe('carol');
    expect(await unwrapShare(key, next.row, next.wrapped)).toEqual(share);
    await expect(unwrapShare(key, open, next.wrapped)).rejects.toThrow(); // SHOULD FAIL: the old binding is gone
    await expect(rebindRecipient(key, next.row, next.wrapped, 'mallory')).rejects.toThrow(/already has a recipient/); // SHOULD FAIL
  });
});

describe('who may have the share, and when', () => {
  it('nobody before the unlock time, not even the owner', () => {
    expect(mayRelease(row, who('alice'), 1_999)).toEqual({ ok: false, status: 425, reason: 'Still locked.' });
    expect(mayRelease({ ...row, policy: 'public' }, null, 1_999).ok).toBe(false);
  });
  it('after it: the owner and the recipient', () => {
    expect(mayRelease(row, who('alice'), 2_000).ok).toBe(true);
    expect(mayRelease(row, who('bob'), 2_000).ok).toBe(true);
  });
  it('SHOULD FAIL: a stranger (403) or an anonymous caller (401) after unlock, on a parties capsule', () => {
    expect(mayRelease(row, who('mallory'), 3_000)).toMatchObject({ ok: false, status: 403 });
    expect(mayRelease(row, null, 3_000)).toMatchObject({ ok: false, status: 401 });
  });
  it('a public capsule: anyone after unlock', () => {
    expect(mayRelease({ ...row, policy: 'public' }, null, 2_000).ok).toBe(true);
  });
  it('an email recipient: only a caller whose VERIFIED email matches', () => {
    const byEmail = { ...row, recipient_id: null, recipient_email: 'bob@example.com' };
    expect(mayRelease(byEmail, who('new-bob', 'bob@example.com'), 3_000).ok).toBe(true);
    expect(mayRelease(byEmail, who('eve', null), 3_000).ok).toBe(false); // SHOULD FAIL: unverified
    expect(mayRelease(byEmail, who('eve', 'eve@example.com'), 3_000).ok).toBe(false); // SHOULD FAIL
  });
  it('a password capsule (no time lock): only with the password matched, whoever asks', () => {
    const pw = { ...row, policy: 'public' as const, unlock_ms: 0, password_verifier: 'v' };
    expect(mayRelease(pw, null, 1, true).ok).toBe(true);
    expect(mayRelease(pw, null, 1, false)).toMatchObject({ ok: false, status: 403 }); // SHOULD FAIL
    expect(mayRelease({ ...pw, policy: 'parties' }, who('alice'), 1, false).ok).toBe(false); // SHOULD FAIL: even the owner
  });
});
