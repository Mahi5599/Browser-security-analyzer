import "@testing-library/jest-dom/vitest";
import { webcrypto } from "node:crypto";

// jsdom does not always expose SubtleCrypto; the app needs crypto.subtle for the export hash.
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}
