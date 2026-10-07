/** How long a browser has to come back from the login page before the ask expires. */
export declare const REAUTH_ASK_TTL_MS: number;
/**
 * Key prefix separating ask records from the sessions sharing the store.
 *
 * express-session generates its ids with `uid-safe`, which emits only
 * base64url characters, so no session id can collide with a key carrying this
 * prefix — the same reasoning as the federation transaction's prefix.
 */
export declare const REAUTH_ASK_KEY_PREFIX = "reauth:";
/** The query parameter naming the ask on the URL the login page returns to. */
export declare const REAUTH_ASK_PARAM = "reauth_ask";
export interface ReauthAskRecord {
    /**
     * Epoch milliseconds at which this endpoint asked for a re-authentication.
     * Milliseconds, not seconds: an authentication must come strictly after the
     * ask, and in whole seconds a session created earlier in the same second
     * compared equal (v0.13.0 audit).
     */
    readonly askedAt: number;
    /**
     * The canonical authorize request the ask was minted for, without the ask
     * parameter itself. A return to a different request finds nothing.
     */
    readonly request: string;
}
/**
 * The slice of an express-session `Store` this module uses.
 *
 * Structural rather than `import type { Store }`, so a composition root may
 * hand over any store-shaped object and a test harness can supply one without
 * subclassing an abstract class.
 */
export interface ReauthAskSessionStore {
    get(sid: string, callback: (err: unknown, record?: unknown) => void): void;
    set(sid: string, record: unknown, callback?: (err?: unknown) => void): void;
    destroy(sid: string, callback?: (err?: unknown) => void): void;
}
export interface ReauthAskStore {
    /** Mint an id, record the ask under it, and return the id. */
    ask(record: ReauthAskRecord): Promise<string>;
    /**
     * The ask `id` names, if it is for `request` — removed in the same step, so
     * a replay finds nothing. `null` when there is no such ask, when it was
     * minted for another request, or when it has expired.
     */
    consume(id: string, request: string): Promise<ReauthAskRecord | null>;
}
/**
 * Adapt the express-session store the deployment already runs into an ask
 * store.
 *
 * The record is shaped like a session — an envelope beside a `cookie` bearing
 * `expires` — because that shape is what the store implementations read to
 * decide when a record dies: `MemoryStore` drops one whose `cookie.expires`
 * has passed on the next read, and `connect-redis` turns the same field into
 * the key's `EX`. An abandoned ask is therefore reaped by the store itself,
 * with no sweeper of ours, in both deployments. The same envelope the
 * federation transaction uses (#494).
 */
export declare const createReauthAskStore: (store: ReauthAskSessionStore) => ReauthAskStore;
/**
 * The ask store behind this request, or `undefined` when no session middleware
 * mounted one. A request that reaches `/authorize` without a session store has
 * no composition to record an ask in, which is a composition error rather than
 * a per-request condition — the endpoint refuses rather than proceeding.
 */
export declare const reauthAskStoreFor: (req: unknown) => ReauthAskStore | undefined;
//# sourceMappingURL=reauthAsk.d.mts.map