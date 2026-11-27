import tseslint from 'typescript-eslint';
import jsxA11y from 'eslint-plugin-jsx-a11y';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import noRawColors from './eslint-rules/no-raw-colors.js';
import { RAW_COLORS_BASELINE } from './eslint-rules/raw-colors-baseline.mjs';
import * as noRawKvAccess from './eslint-rules/no-raw-kv-access.js';
import { KV_ALLOW_FILES } from './eslint-rules/kv-policy.js';

export default tseslint.config(
  {
    ignores: [
      'dist',
      '.ssr-build',
      'node_modules',
      // Vendored coding-agent skills (e.g. security-audit's zero-dependency
      // CommonJS validators) are third-party tooling, not repo source.
      '.agents/skills/**',
      'public/tesseract',
      'worker-configuration.d.ts',
      '*.config.*',
      'scripts/',
      '.wrangler-dryrun/',
      '.wrangler/',
      'public/sw.js',
      'threat-intel-staging/**',
      'security-investigator-replication/**',
      'public/dfir/**',
      'public/data/cyberview/source/**',
    ],
  },

  // Base TS + recommended rules (brings in @typescript-eslint plugin automatically)
  ...tseslint.configs.recommended,

  // Typed-linting for source files (excludes test files not in tsconfig)
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['**/__tests__/**', '**/*.test.ts', '**/*.test.tsx', 'src/test/**'],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
      'jsx-a11y': jsxA11y,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/purity': 'off',
      'react-hooks/static-components': 'off',
      'react-hooks/immutability': 'off',
      'react-hooks/refs': 'off',
      'react-hooks/set-state-in-render': 'off',
      'react-hooks/preserve-manual-memoization': 'off',
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-expressions': 'off',
      'prefer-const': 'warn',
      'no-var': 'warn',
      'jsx-a11y/anchor-is-valid': 'off',
      'jsx-a11y/scope': 'warn',
      'jsx-a11y/no-redundant-roles': 'warn',
      'jsx-a11y/alt-text': 'warn',
      'no-raw-colors/no-raw-colors': 'warn',
    },
    settings: {
      'jsx-a11y': {
        components: {
          ThemeToggle: 'button',
          BackToTop: 'button',
        },
      },
    },
  },

  // Custom ESLint plugins
  {
    plugins: {
      'no-raw-colors': {
        rules: {
          'no-raw-colors': noRawColors,
        },
      },
      'no-raw-kv-access': {
        rules: {
          'no-raw-kv-access': noRawKvAccess.default,
        },
      },
    },
  },

  // Legacy raw-palette debt: `no-raw-colors` stays ON repo-wide, but is
  // waived for the 203 files that already carried raw palette colours before
  // the rule landed. Scoping the waiver to a list (rather than setting the
  // rule to 'off') is what keeps it catching NEW raw colours - the actual
  // value - including in any file created after the baseline.
  //
  // CI runs `--max-warnings 0`, so without this waiver every push fails on
  // pre-existing findings. Shrink the list as files are cleaned up:
  //     node scripts/update-raw-colors-baseline.mjs
  // and delete this block once the script reports zero.
  //
  // See eslint-rules/raw-colors-baseline.mjs for why a blanket `--fix` is not
  // safe here (state variants like `hover:` are not themes, and
  // `bg-white ... dark:bg-transparent` is not the same as `bg-surface-100`).
  {
    files: RAW_COLORS_BASELINE,
    rules: {
      'no-raw-colors/no-raw-colors': 'off',
    },
  },

  // KV policy guardrail for worker/** (CLAUDE.md "KV policy — Cache API
  // first"). api/** is governed by api/eslint.config.js (flat-config
  // cascading: nearest eslint.config.js wins per subtree) — the allowlist is
  // shared via eslint-rules/kv-policy.js so both stay in sync.
  {
    files: ['worker/**/*.ts'],
    ignores: ['**/*.test.ts', '**/*.test.tsx', '**/__tests__/**'],
    rules: {
      'no-raw-kv-access/no-raw-kv-access': ['error', { allowFiles: KV_ALLOW_FILES }],
    },
  },

  // Worker files (not in src/, but part of the project)
  {
    files: ['worker/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },

  // Lazy-only vendor restrictions (applied to all source)
  {
    files: ['src/**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: '@xyflow/react',
              message: 'Load @xyflow/react only via React.lazy in StixGraph.tsx.',
              allowTypeImports: true,
            },
            {
              name: 'react-simple-maps',
              message: 'Load react-simple-maps only via React.lazy in ThreatMapChart.tsx.',
              allowTypeImports: true,
            },
            {
              name: 'marked',
              message: 'Load marked only via dynamic import inside WikiArticle effect.',
              allowTypeImports: true,
            },
            {
              name: 'isomorphic-dompurify',
              message: 'Load isomorphic-dompurify only via dynamic import inside WikiArticle effect.',
              allowTypeImports: true,
            },
            {
              name: 'exifr',
              message: 'Load exifr lazily inside the file-drop handler in ExifParse.tsx.',
              allowTypeImports: true,
            },
          ],
        },
      ],
    },
  },

  // Allowlist lazy entry points
  {
    files: [
      'src/pages/dfir/StixGraph.tsx',
      'src/pages/dfir/ThreatMapChart.tsx',
      'src/pages/threatintel/RelationshipGraphCanvas.tsx',
      'src/components/dfir/osint/IdentifierNode.tsx',
      'src/components/dfir/osint/IdentifierGraph.tsx',
      'src/pages/dfir/ReportAnalyzer.tsx',
      'src/pages/threatintel/KnowledgeGraph.tsx',
      'src/components/flowviz/FlowVizCanvas.tsx',
      'src/components/dfir/RelationshipGraph.tsx',
    ],
    rules: {
      '@typescript-eslint/no-restricted-imports': 'off',
    },
  },

  // Test files (no projectService, relaxed rules)
  {
    files: ['**/__tests__/**/*.{ts,tsx}', '**/*.test.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  }
);
