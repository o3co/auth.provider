import type { WebAuthnCredentialStore } from "./types.mjs";
/**
 * In-process Map-backed WebAuthnCredentialStore.
 *
 * Atomicity argument (single-process, single-event-loop):
 *   - `registerCredential`: the Map.has check and Map.set are SYNCHRONOUS —
 *     no `await` between them. Node's microtask queue cannot interleave
 *     non-async work, so concurrent callers do not race.
 *   - `updateSignCount` is an atomic compare-and-set (CAS) under the same
 *     guarantee.
 *   - Production deployments requiring multi-process or distributed
 *     deployments should use a real backing store (e.g. a Redis adapter).
 *
 * `remove` is idempotent: deleting a non-existent credentialId is a no-op.
 */
export declare function createMemoryWebAuthnCredentialStore(): WebAuthnCredentialStore;
//# sourceMappingURL=memory.d.mts.map