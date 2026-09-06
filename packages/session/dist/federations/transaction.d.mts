/**
 * How long a federation transaction may sit unconsumed.
 *
 * The window a user has between being redirected to the IdP and coming back:
 * long enough to type a password and satisfy the IdP's own MFA, short enough
 * that an abandoned flow leaves nothing meaningful behind. It bounds the
 * transaction cookie's `Max-Age` and the stored record's expiry together, so
 * neither can outlive the other.
 */
export declare const DEFAULT_FEDERATION_TRANSACTION_TTL_MS = 600000;
/**
 * Key prefix separating transaction records from the sessions sharing the
 * store.
 *
 * express-session generates its ids with `uid-safe`, which emits only
 * base64url characters, so no session id can ever collide with a key that
 * carries this prefix.
 */
export declare const FEDERATION_TRANSACTION_KEY_PREFIX = "fedtx:";
/** Appended to the deployment's session cookie name — cf. `<session.name>.csrf`. */
export declare const FEDERATION_TRANSACTION_COOKIE_SUFFIX = ".federation";
/** The ephemeral state a federation callback needs to complete the flow. */
export interface FederationTransactionEnvelope {
    readonly name: string;
    readonly state: string;
    readonly codeVerifier: string;
    /** PB-4 nonce — absent for OAuth-only providers. */
    readonly nonce?: string | undefined;
    readonly redirectTo?: string | undefined;
}
/**
 * The slice of an express-session `Store` this module uses.
 *
 * Structural rather than `import type { Store }` so a composition root may
 * hand over any store-shaped object, and so the harnesses in `__tests__` can
 * supply one without subclassing an abstract class.
 */
export interface FederationTransactionSessionStore {
    get(sid: string, callback: (err: unknown, record?: unknown) => void): void;
    set(sid: string, record: unknown, callback?: (err?: unknown) => void): void;
    destroy(sid: string, callback?: (err?: unknown) => void): void;
}
export interface FederationTransactionStore {
    /** Persist an envelope under `id`, expiring `ttlMs` from now. */
    set(id: string, envelope: FederationTransactionEnvelope, ttlMs: number): Promise<void>;
    /** Read an envelope back, or `null` when there is none to read. */
    get(id: string): Promise<FederationTransactionEnvelope | null>;
    /**
     * Remove the record. Rejects when the store refuses, so the caller can
     * decide whether an un-deletable — and therefore replayable — transaction
     * is fatal. It is, on the path that consumes one.
     */
    delete(id: string): Promise<void>;
}
/**
 * Mint an opaque, single-use transaction id.
 *
 * 256 bits from the CSPRNG. The id is a bearer value — presenting it is what
 * proves the callback reached the browser that started the flow — so it is
 * sized like one, not like the 128-bit `state` it accompanies.
 */
export declare const mintFederationTransactionId: () => string;
/**
 * Name the transaction cookie after the deployment's session cookie, the way
 * the CSRF cookie is named: `<session.name>.federation`, so it inherits the
 * operator's naming rather than introducing an unrelated one.
 *
 * The prefix is the deviation, and it is deliberate. Any prefix the session
 * name carries is stripped and `__Secure-` is applied **unconditionally**, so
 * the result is always `__Secure-<base>.federation` — including for a session
 * cookie named with no prefix at all.
 *
 * `__Secure-` rather than `__Host-`, because `__Host-` requires `Path=/` and
 * this cookie is deliberately path-scoped to the callback route; a `__Host-`
 * name would be silently dropped by every browser and the callback would fail
 * with nothing visibly wrong. Unconditionally, because unlike the session
 * cookie — whose `Secure` flag is the operator's `session.secure` to set — this
 * cookie is `SameSite=None` and therefore *always* issued with `Secure`. The
 * prefix states that invariant where a browser will enforce it, so the cookie
 * cannot be set over a plain-HTTP hop by anything, including an attacker in a
 * position to inject one.
 */
export declare const deriveFederationTransactionCookieName: (sessionCookieName: string) => string;
/**
 * Adapt the express-session store the deployment already runs into a
 * transaction store.
 *
 * The record is shaped like a session — an envelope beside a `cookie` bearing
 * `expires` — because that shape is what the store implementations read to
 * decide when a record dies. `MemoryStore` drops a record whose
 * `cookie.expires` has passed on the next read; `connect-redis` turns the same
 * field into the Redis key's `EX`. Writing the expiry there means an abandoned
 * transaction is reaped by the store itself, with no sweeper of ours, in both
 * deployments.
 */
export declare const createFederationTransactionStore: (store: FederationTransactionSessionStore) => FederationTransactionStore;
//# sourceMappingURL=transaction.d.mts.map