/**
 * Capsule passwords (D-088): a gate, never key material (OFF-ICP-PLAN §2).
 *
 * Stored only as a slow PBKDF2-SHA-256 verifier, self-describing so the
 * iteration count can rise later without breaking old capsules. A stolen
 * database gives an attacker this verifier to guess against offline, and a
 * correct guess still opens nothing: it only gets them to capsl's release
 * endpoint, which also checks the date, the caller and the rate limits.
 */

/**
 * 🔴 CLOUDFLARE CAPS PBKDF2 AT 100,000 ITERATIONS, AND ONLY IN PRODUCTION. Live
 * staging refused 600,000 with "iteration counts above 100000 are not supported";
 * the local runtime the tests use accepts any count (2026-10-27). OWASP's figure
 * is 600,000, so this verifier is weaker against offline guessing than that
 * advice. It is still only a gate: a correct guess opens nothing alone (§3.2).
 */
export const ITERATIONS = 100_000;
export const CLOUDFLARE_PBKDF2_MAX = 100_000;
const SALT_BYTES = 16;
const HASH_BYTES = 32;
export const PASSWORD_MAX = 200;

const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations }, key, HASH_BYTES * 8,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password: string, iterations = ITERATIONS): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  return `pbkdf2-sha256:${iterations}:${b64(salt)}:${b64(await derive(password, salt, iterations))}`;
}

/** Constant-time compare; false for any verifier this code does not recognise. */
export async function verifyPassword(password: string, verifier: string): Promise<boolean> {
  const m = /^pbkdf2-sha256:(\d+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/.exec(verifier);
  if (!m) return false;
  const iterations = Number(m[1]);
  if (!Number.isSafeInteger(iterations) || iterations < 1) return false;
  const want = unb64(m[3]);
  const got = await derive(password, unb64(m[2]), iterations);
  let diff = want.length ^ got.length;
  for (let i = 0; i < Math.max(want.length, got.length); i++) diff |= (want[i] ?? 0) ^ (got[i] ?? 0);
  return diff === 0;
}
