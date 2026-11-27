import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  define: {
    __BUILD_DATE__: JSON.stringify(new Date().toISOString().slice(0, 10)),
  },
  test: {
    testTimeout: 10_000,
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    // The /api package runs under @cloudflare/vitest-pool-workers
    // (own vitest.config.ts) and uses imports like `cloudflare:test`
    // that don't resolve in this jsdom runner. Exclude its tree so a
    // root-level `npm test` doesn't try to load worker tests here.
    // Vendored agent skills are third-party tooling, not repo test suites.
    exclude: ['**/node_modules/**', '**/dist/**', '**/.agents/**', 'api/**', 'scripts/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      // Thresholds are intentionally loose at the global level — the
      // rule-convert module has its own dedicated suite with deeper
      // assertions, so its real coverage is much higher than the
      // whole-tree average. The global threshold is a tripwire that
      // catches accidental drops in any subtree.
      thresholds: {
        lines: 30,
        functions: 30,
        branches: 25,
        statements: 30,
      },
      exclude: [
        'node_modules/',
        'src/test/',
        'api/**',
        '**/*.d.ts',
        '**/*.config.*',
        '**/dist/**',
        // Generated / test fixtures
        '**/*.test.{ts,tsx}',
        '**/__tests__/**',
        // Page components are tested via the e2e pipeline, not vitest
        'src/pages/**',
        'src/components/**',
        // Routing layer
        'src/App.tsx',
        'src/main.tsx',
        'src/entry-server.tsx',
        // Generated content (case studies, research) lives in data files
        'src/data/**',
      ],
    },
  },
});
