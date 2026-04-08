import tseslint from "typescript-eslint";
import prettierConfig from "eslint-config-prettier";

export default tseslint.config(
  // ── Ignored paths ─────────────────────────────────────────────────
  { ignores: ["dist/**", "node_modules/**"] },

  // ── Type-aware recommended rules ──────────────────────────────────
  ...tseslint.configs.recommendedTypeChecked,

  // ── Project-level overrides ───────────────────────────────────────
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Protocol code must never use raw console — use logger.ts
      "no-console": "error",

      // Allow _-prefixed intentional discards (e.g. const { sig: _sig, ...rest } = token)
      "@typescript-eslint/no-unused-vars": [
        "error",
        { varsIgnorePattern: "^_", argsIgnorePattern: "^_" },
      ],

      // Floating promises are a correctness risk in crypto code
      "@typescript-eslint/no-floating-promises": "error",

      // Protocol primitives must be fully typed — no any escape hatches
      "@typescript-eslint/no-explicit-any": "error",
    },
  },

  // ── Prettier — must be last ────────────────────────────────────────
  prettierConfig,
);
