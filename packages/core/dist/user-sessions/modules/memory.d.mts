/**
 * Bundled module providing all 4 in-memory user-session stores. Single-decision
 * wiring for the common case (Codex Q4 finding). Per A4 §8.1 + §8.2.
 *
 * For mixed wiring (e.g. memory userSessionStore + redis indexes), use
 * `overrideComponents` per A4 §8.3 — `provides[K]` is skipped when an
 * override is supplied for K.
 */
export declare const memorySessionStoresModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=memory.d.mts.map