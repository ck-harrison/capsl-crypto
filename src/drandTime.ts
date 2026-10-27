/**
 * The `time` factor after ICP: drand quicknet via tlock (D-087, docs/OFF-ICP-PLAN.md §2).
 *
 * Plugs into `timeSealer` / `timeOpener` in `frontend/src/utils/capsuleEnvelope.ts`
 * unchanged: the share is encrypted to the drand round at (or just after) the
 * unlock time, and nobody, capsl included, can decrypt it before drand publishes
 * that round.
 *
 * Browser-side code. It lives here for the phase 0 spike and moves to the
 * frontend in phase 2.
 *
 * `mainnetClient()` pins quicknet's chain hash AND public key, so a relay cannot
 * feed a forged beacon: every beacon is BLS-verified against the pinned key.
 */
import { timelockEncrypt, timelockDecrypt, mainnetClient, roundAt, roundTime, defaultChainInfo, Buffer } from 'tlock-js';
import type { ChainClient } from 'tlock-js';

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * The first round whose publication time is at or after `unlockMs`.
 *
 * `roundAt` returns the round CURRENT at a time, which is published up to one
 * period BEFORE it. Using it unadjusted would let a capsule open up to 3s early.
 */
export function roundForUnlock(unlockMs: number): number {
  const r = roundAt(unlockMs, defaultChainInfo);
  return roundTime(defaultChainInfo, r) >= unlockMs ? r : r + 1;
}

/**
 * Bound into the combiner as the factor's "public key", so the round and the
 * chain are covered by the header MAC and cannot be swapped.
 */
export function drandBinding(round: number): Uint8Array {
  return enc.encode(`drand:${defaultChainInfo.hash}:${round}`);
}

export function drandWrap(unlockMs: number, client: ChainClient = mainnetClient()) {
  return async (share: Uint8Array) => {
    const round = roundForUnlock(unlockMs);
    const armored = await timelockEncrypt(round, Buffer.from(share), client);
    return { ciphertext: enc.encode(armored), publicKey: drandBinding(round) };
  };
}

/** Thrown when drand has not yet published the capsule's round. */
export class TooEarlyError extends Error {}

export function drandUnwrap(client: ChainClient = mainnetClient()) {
  return async (ciphertext: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> => {
    const m = /^drand:([0-9a-f]{64}):(\d+)$/.exec(dec.decode(publicKey));
    if (!m || m[1] !== defaultChainInfo.hash) throw new Error('Not a quicknet time factor.');
    const round = Number(m[2]);
    if (Date.now() < roundTime(defaultChainInfo, round)) {
      throw new TooEarlyError(`Opens at ${new Date(roundTime(defaultChainInfo, round)).toISOString()}.`);
    }
    try {
      return new Uint8Array(await timelockDecrypt(dec.decode(ciphertext), client));
    } catch (e) {
      // tlock refuses a round that is not out yet; anything else is a real failure.
      if (/too early|not.*reached|future/i.test(String(e))) throw new TooEarlyError(String(e));
      throw e;
    }
  };
}
