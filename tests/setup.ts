// tests/setup.ts
// Polyfill WebCrypto for Vitest's Node VM sandbox.
// Node 18 has globalThis.crypto on the host but Vitest isolates each test
// file in a V8 context that does not inherit it automatically.
// This file is loaded via vitest.config.ts setupFiles — never shipped to dist/.
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).crypto = webcrypto;
}
