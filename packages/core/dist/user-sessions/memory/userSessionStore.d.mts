import type { UserSessionStore } from "../types.mjs";
/**
 * In-memory UserSessionStore. Single-process only. Atomicity comes from
 * Node's single event loop — `Map.get/set/delete` are synchronous.
 *
 * Per A4 §5.1 + §7.1 (lines 469-505).
 */
export declare function createInMemoryUserSessionStore(): UserSessionStore;
//# sourceMappingURL=userSessionStore.d.mts.map