import tseslint from 'typescript-eslint';
import * as noRawKvAccess from '../eslint-rules/no-raw-kv-access.js';
import { KV_ALLOW_FILES } from '../eslint-rules/kv-policy.js';

export default tseslint.config(
  { ignores: ['**/*.test.ts', '**/*.d.ts'] },
  {
    extends: [...tseslint.configs.recommended],
    files: ['src/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        fetch: 'readonly',
        Response: 'readonly',
        Request: 'readonly',
        Headers: 'readonly',
        URL: 'readonly',
        URLSearchParams: 'readonly',
        TextEncoder: 'readonly',
        TextDecoder: 'readonly',
        crypto: 'readonly',
        Crypto: 'readonly',
        CryptoKey: 'readonly',
        SubtleCrypto: 'readonly',
        Cache: 'readonly',
        caches: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        AbortController: 'readonly',
        AbortSignal: 'readonly',
        ReadableStream: 'readonly',
        WritableStream: 'readonly',
        TransformStream: 'readonly',
        atob: 'readonly',
        btoa: 'readonly',
        Blob: 'readonly',
        File: 'readonly',
        FormData: 'readonly',
        RequestInfo: 'readonly',
        RequestInit: 'readonly',
        ResponseInit: 'readonly',
        structuredClone: 'readonly',
        D1Database: 'readonly',
        D1Result: 'readonly',
        D1PreparedStatement: 'readonly',
        KVNamespace: 'readonly',
        R2Bucket: 'readonly',
        R2Object: 'readonly',
        Queue: 'readonly',
        Fetcher: 'readonly',
        DurableObjectNamespace: 'readonly',
        DurableObject: 'readonly',
        DurableObjectState: 'readonly',
        Ai: 'readonly',
        VectorizeIndex: 'readonly',
        AnalyticsEngineDataset: 'readonly',
        Event: 'readonly',
        FetchEvent: 'readonly',
        ScheduledEvent: 'readonly',
        ExecutionContext: 'readonly',
        // Workers HTMLRewriter + the DOM types its element handlers receive.
        // Missing these made `no-undef` fire on correct code.
        HTMLRewriter: 'readonly',
        Element: 'readonly',
        HTMLElement: 'readonly',
        Node: 'readonly',
        Text: 'readonly',
        performance: 'readonly',
        Buffer: 'readonly',
        process: 'readonly',
        console: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-require-imports': 'off',

      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],
      'no-unused-vars': 'off',
      'no-throw-literal': 'error',

      '@typescript-eslint/await-thenable': 'warn',
      '@typescript-eslint/no-floating-promises': 'warn',
      '@typescript-eslint/no-misused-promises': 'warn',

      'no-console': 'off',
      'prefer-const': 'warn',
      'no-var': 'warn',
      'prefer-rest-params': 'warn',
      'prefer-spread': 'warn',
      'no-undef': 'warn',
      // skipRegExps: an invisible character inside a regex is usually
      // deliberate, not a typo. A non-breaking space in `/[ \t\u00A0]+/g`
      // is the author asking to collapse NBSPs, and the rule was failing it.
      'no-irregular-whitespace': ['warn', { skipRegExps: true }],
      '@typescript-eslint/prefer-as-const': 'warn',
      '@typescript-eslint/no-unnecessary-type-constraint': 'warn',
      '@typescript-eslint/ban-ts-comment': 'warn',
      '@typescript-eslint/no-non-null-asserted-optional-chain': 'warn',
    },
  },
  // Non-`*.test.ts` helpers in test/ (e.g. test-helpers.ts) match no block
  // above, so directory traversal parsed them with the default espree parser
  // (TS syntax → "Parsing error"). Give the rest of test/ the lint rules too.
  {
    files: ['test/**/*.{ts,tsx}'],
    plugins: {
      '@typescript-eslint': tseslint.plugin,
    },
    languageOptions: {
      parser: tseslint.parser,
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },

  // KV policy guardrail — MUST mirror the root eslint.config.js block (flat-
  // config cascading means api/** files resolve to THIS config, so without
  // this block api/src silently loses the guardrail). See
  // eslint-rules/kv-policy.js for the shared allowlist and its rationale.
  {
    plugins: {
      'no-raw-kv-access': {
        rules: {
          'no-raw-kv-access': noRawKvAccess.default,
        },
      },
    },
  },
  {
    files: ['src/**/*.ts'],
    ignores: ['**/*.test.ts'],
    rules: {
      'no-raw-kv-access/no-raw-kv-access': ['error', { allowFiles: KV_ALLOW_FILES }],
    },
  }
);
