import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.js'],
    coverage: {
      provider: 'v8',
      exclude: [
        'tests/**',
        'dist/**',
        // Pure re-export "barrel" file, no logic of its own.
        'index.js',
        // Vendored/generated data (Mustache template strings, CSS).
        'lib/templates/**',
        'lib/css/**',
      ],
    },
  },
})
