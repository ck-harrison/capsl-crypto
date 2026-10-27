/**
 * The drand `time` factor inside the REAL capsule envelope
 * (`frontend/src/utils/capsuleEnvelope.ts`), against the live quicknet network.
 *
 * Seals a capsule with `time` (drand, unlocking ~9s out) + `release`, then shows:
 * it cannot open early, even bypassing our own date check; it opens on time; and
 * the drand share alone is not enough (the two-locks claim, OFF-ICP-PLAN §2).
 */
import { describe, expect, it } from 'vitest';
import { timelockDecrypt, mainnetClient, roundTime, defaultChainInfo } from 'tlock-js';
import {
  sealCapsule, openCapsule, timeSealer, timeOpener, type FactorSealer, type FactorOpener,
} from '../src/capsuleEnvelope';
import { drandUnwrap, drandWrap, roundForUnlock, TooEarlyError, drandBinding } from '../src/drandTime';

function releaseFactor(share: Uint8Array): FactorSealer & FactorOpener {
  return {
    kind: 'release',
    async seal() { return { share, ciphertext: new Uint8Array(0), publicKey: new Uint8Array(0) }; },
    async open() { return share; },
  };
}

function splitParams(params: Uint8Array): { ciphertext: Uint8Array } {
  // Envelope params are [u32 len][ciphertext][u32 len][publicKey]; same codec as capsuleEnvelope.ts.
  const view = new DataView(params.buffer, params.byteOffset, params.byteLength);
  const len = view.getUint32(0);
  return { ciphertext: params.slice(4, 4 + len) };
}

describe("the server's copy of quicknet's constants (src/drandRound.ts)", () => {
  it('matches tlock-js, and picks the same round as the browser for every moment tried', async () => {
    const { QUICKNET, roundForUnlockMs, roundTimeMs } = await import('../src/drandRound');
    expect(QUICKNET).toEqual({ hash: defaultChainInfo.hash, genesisMs: defaultChainInfo.genesis_time * 1000, periodMs: defaultChainInfo.period * 1000 });
    for (let t = 1_800_000_000_000; t < 1_800_000_000_000 + 9_000; t += 137) {
      expect(roundForUnlockMs(t)).toBe(roundForUnlock(t));
      expect(roundTimeMs(roundForUnlockMs(t))).toBe(roundTime(defaultChainInfo, roundForUnlock(t)));
    }
  });
});

describe('roundForUnlock', () => {
  it('never picks a round published before the unlock time', () => {
    for (let t = 1_800_000_000_000; t < 1_800_000_000_000 + 7_000; t += 250) {
      const r = roundForUnlock(t);
      expect(roundTime(defaultChainInfo, r)).toBeGreaterThanOrEqual(t);
      expect(roundTime(defaultChainInfo, r - 1)).toBeLessThan(t);
    }
  });
});

describe('drand time factor in the capsule envelope (live quicknet)', () => {
  it('stays shut before the round, opens after it, and needs the release share too', async () => {
    const client = mainnetClient();
    const unlockMs = Date.now() + 9_000;
    const release = crypto.getRandomValues(new Uint8Array(32));
    const { crypto: envelope } = await sealCapsule('env-1', 'hello from the past', [
      timeSealer(drandWrap(unlockMs, client)),
      releaseFactor(release),
    ]);

    // SHOULD FAIL: our own date check refuses early.
    await expect(openCapsule('env-1', envelope, [timeOpener(drandUnwrap(client)), releaseFactor(release)]))
      .rejects.toBeInstanceOf(TooEarlyError);

    // SHOULD FAIL: and so does the cryptography itself, with our check bypassed.
    const timeCt = new TextDecoder().decode(splitParams(envelope.factors[0].params).ciphertext);
    await expect(timelockDecrypt(timeCt, client)).rejects.toThrow();

    const round = roundForUnlock(unlockMs);
    await new Promise((r) => setTimeout(r, roundTime(defaultChainInfo, round) - Date.now() + 4_000));

    const opened = await openCapsule('env-1', envelope, [timeOpener(drandUnwrap(client)), releaseFactor(release)]);
    expect(opened.plaintext).toBe('hello from the past');

    // SHOULD FAIL: after the date, drand alone (wrong release share) does not open it.
    const wrong = releaseFactor(crypto.getRandomValues(new Uint8Array(32)));
    await expect(openCapsule('env-1', envelope, [timeOpener(drandUnwrap(client)), wrong])).rejects.toThrow();
  });

  it('SHOULD FAIL: a time factor bound to a different round is rejected', async () => {
    const unwrap = drandUnwrap(mainnetClient());
    await expect(unwrap(new Uint8Array(0), new TextEncoder().encode('drand:' + '0'.repeat(64) + ':1'))).rejects.toThrow(/quicknet/);
    // A far-future round is refused before any network call.
    await expect(unwrap(new Uint8Array(0), drandBinding(roundForUnlock(Date.now() + 3_600_000))))
      .rejects.toBeInstanceOf(TooEarlyError);
  });
});
