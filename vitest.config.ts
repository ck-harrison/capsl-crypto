import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      { test: { name: 'offline', include: ['test/capsuleEnvelope.test.ts', 'test/release.test.ts'], environment: 'node' } },
      // Waits for a real drand round on the live quicknet network (about 15 seconds).
      { test: { name: 'drand', include: ['test/drand.test.ts'], environment: 'node', testTimeout: 90_000 } },
    ],
  },
});
