/**
 * In-process {@link FederationGrantIntentStore} (#593, D16, slice 6).
 *
 * Dev, test and single-replica only: what it holds is one browser's flow — a
 * PKCE verifier, a nonce, the consent challenge — so a second replica answers
 * every callback the first one started with "unknown transaction", and a
 * restart loses flows in flight. It loses no established grant, which is why
 * this adapter beside a durable grant store is permitted for a single replica
 * and refused by name under `deployment.mode = "multi"`.
 *
 * Every transition below is one synchronous critical section taken before the
 * promise resolves: the operations this port makes atomic are atomic here
 * because nothing awaits inside them.
 */
import { type FederationGrantIntentStore } from "./intentStore.mjs";
/**
 * Sweep once this many entries are resident, and again each time that has
 * doubled: a connect the user never finishes leaves an entry nobody reads
 * again, under a handle nobody lodges again, and reclaiming on touch alone
 * would keep every one of them. Amortized, with no timer of its own, as the
 * grant store's and the pending-consent store's are.
 */
export declare const MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR = 1024;
/** In-process intent store, with what is resident exposed for observability. */
export interface MemoryFederationGrantIntentStore extends FederationGrantIntentStore {
    /** Entries currently resident, reclaimable-but-unreclaimed included. */
    readonly size: number;
    /**
     * Whether anything is THERE under the handle — a live record or the marker a
     * spent one leaves. What makes a handle taken, which is not the same as what
     * a caller can see.
     */
    holdsIntent(handle: string): boolean;
    holdsConsent(challenge: string): boolean;
    /** Whether the transaction — and with it its verifier and nonce — is still held. */
    holdsTransaction(state: string): boolean;
    /** Reservations against the bound for the pair, on this store's own clock. */
    reservations(clientId: string, subject: string): number;
}
export declare function createMemoryFederationGrantIntentStore(): MemoryFederationGrantIntentStore;
//# sourceMappingURL=intentMemory.d.mts.map