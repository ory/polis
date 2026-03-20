const nextCoreWebVitals = require('eslint-config-next/core-web-vitals');
const i18Next = require('eslint-plugin-i18next');
const globals = require('globals');
const tsParser = require('@typescript-eslint/parser');
const js = require('@eslint/js');

const { FlatCompat } = require('@eslint/eslintrc');

const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
});

module.exports = [
  {
    ignores: [
      '.next',
      '**/node_modules',
      '**/dist',
      'npm/dist',
      'npm/migration',
      'internal-ui/dist',
      'eslint.config.cjs',
      'node_modules/**',
      '.next/**',
      'out/**',
      'build/**',
      'next-env.d.ts',
    ],
  },
  ...compat.extends('eslint:recommended'),
  ...compat.extends('prettier'),
  ...nextCoreWebVitals,
  ...compat.extends('plugin:i18next/recommended'),
  {
    plugins: {
      i18next: i18Next,
    },

    languageOptions: {
      globals: {
        ...globals.node,
      },

      parser: tsParser,
      ecmaVersion: 13,
      sourceType: 'module',
    },
  },
  {
    files: ['**/*.ts', '**/*.tsx'],

    rules: {
      'no-undef': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'off',
      'import/no-anonymous-default-export': 'off',
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
  {
    files: ['**/*.js'],

    rules: {
      '@typescript-eslint/no-var-requires': 'off',
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
  {
    files: ['sdk/**/*'],

    rules: {
      '@next/next/no-img-element': 'off',
    },
  },
];
