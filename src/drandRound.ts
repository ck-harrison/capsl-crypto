/**
 * drand quicknet round arithmetic for the SERVER (D-087 phase 2).
 *
 * The server never decrypts a time factor; it only checks, when a capsule is
 * sealed, that the browser bound it to the right round. Without that check a
 * buggy or hostile client could seal a capsule "for 2040" to a round already
 * published, and the time lock would be decoration.
 *
 * Constants are quicknet's chain info (the same values `tlock-js` exports as
 * `defaultChainInfo`; the test compares them), copied so the Worker bundle does
 * not pull in the drand client.
 */

export const QUICKNET = {
  hash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  genesisMs: 1_692_803_367_000,
  periodMs: 3_000,
} as const;

/** When `round` is published. Round 1 is at genesis. */
export function roundTimeMs(round: number): number {
  return QUICKNET.genesisMs + (round - 1) * QUICKNET.periodMs;
}

/** The first round published at or after `unlockMs` (same rule as `drandTime.roundForUnlock`). */
export function roundForUnlockMs(unlockMs: number): number {
  if (unlockMs <= QUICKNET.genesisMs) return 1;
  return Math.ceil((unlockMs - QUICKNET.genesisMs) / QUICKNET.periodMs) + 1;
}

/** The round a stored `time` factor's binding names, or null if it is not a quicknet binding. */
export function parseDrandBinding(publicKey: Uint8Array): number | null {
  const m = /^drand:([0-9a-f]{64}):(\d+)$/.exec(new TextDecoder().decode(publicKey));
  if (!m || m[1] !== QUICKNET.hash) return null;
  const round = Number(m[2]);
  return Number.isSafeInteger(round) && round >= 1 ? round : null;
}
