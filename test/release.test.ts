import { describe, expect, it } from 'vitest';
import { mayRelease, unwrapShare, wrapShare, type ReleaseRow } from '../src/release';

const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const otherKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const row: ReleaseRow = { capsule_id: 'c1', owner_id: 'alice', recipient_id: 'bob', policy: 'parties', unlock_ms: 2_000 };
const share = crypto.getRandomValues(new Uint8Array(32));

describe('release share wrapping', () => {
  it('round-trips under the master key', async () => {
    expect(await unwrapShare(key, row, await wrapShare(key, row, share))).toEqual(share);
  });

  it('SHOULD FAIL: a database edit that moves the unlock time earlier breaks the unwrap', async () => {
    const wrapped = await wrapShare(key, row, share);
    await expect(unwrapShare(key, { ...row, unlock_ms: 1 }, wrapped)).rejects.toThrow();
  });

  it('SHOULD FAIL: re-pointing the recipient or the policy breaks the unwrap', async () => {
    const wrapped = await wrapShare(key, row, share);
    await expect(unwrapShare(key, { ...row, recipient_id: 'mallory' }, wrapped)).rejects.toThrow();
    await expect(unwrapShare(key, { ...row, policy: 'public' }, wrapped)).rejects.toThrow();
  });

  it('SHOULD FAIL: the database alone, without the master key, opens nothing', async () => {
    const wrapped = await wrapShare(key, row, share);
    await expect(unwrapShare(otherKey, row, wrapped)).rejects.toThrow();
    await expect(unwrapShare(undefined, row, wrapped)).rejects.toThrow('RELEASE_MASTER_KEY is not set.');
  });
});

describe('who may have the share, and when', () => {
  it('nobody before the unlock time, not even the owner', () => {
    expect(mayRelease(row, 'alice', 1_999)).toEqual({ ok: false, status: 425, reason: 'Still locked.' });
    expect(mayRelease({ ...row, policy: 'public' }, null, 1_999).ok).toBe(false);
  });
  it('after it: the owner and the recipient', () => {
    expect(mayRelease(row, 'alice', 2_000).ok).toBe(true);
    expect(mayRelease(row, 'bob', 2_000).ok).toBe(true);
  });
  it('SHOULD FAIL: a stranger or an anonymous caller after unlock, on a parties capsule', () => {
    expect(mayRelease(row, 'mallory', 3_000)).toMatchObject({ ok: false, status: 403 });
    expect(mayRelease(row, null, 3_000)).toMatchObject({ ok: false, status: 403 });
  });
  it('a public capsule: anyone after unlock', () => {
    expect(mayRelease({ ...row, policy: 'public' }, null, 2_000).ok).toBe(true);
  });
});
