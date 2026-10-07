import type { JSONWebKeySet } from "jose";
import type { KeyLike } from "../keys/KeyStore.mjs";
/**
 * Where an issuer's signing keys come from (#525).
 *
 * - `key` — one public key, held in memory. The shape `createJwtAssertionVerifier`
 *   has always taken; rotation means re-registering.
 * - `jwks` — a static JSON Web Key Set, for an issuer that publishes several
 *   keys but no endpoint.
 * - `jwks_uri` — a remote JWKS endpoint, fetched on first use and cached. An
 *   unknown `kid` triggers a refetch (bounded by `cooldownMs`), which is how a
 *   rotation at the issuer is picked up without a restart. `https` is required
 *   unless the host is loopback: signing keys fetched over plaintext are keys
 *   an on-path attacker chose.
 */
export type AssertionIssuerKeySource = {
    readonly type: "key";
    readonly key: KeyLike;
} | {
    readonly type: "jwks";
    readonly jwks: JSONWebKeySet;
} | {
    readonly type: "jwks_uri";
    readonly uri: string;
    /** How long a fetched set is served without refetching. Default 10 minutes. */
    readonly cacheMaxAgeMs?: number;
    /** Minimum interval between refetches triggered by an unknown `kid`. Default 30 s. */
    readonly cooldownMs?: number;
    /** Fetch timeout. Default 5 s. */
    readonly timeoutMs?: number;
};
/**
 * One issuer this deployment accepts RFC 7523 assertions from, and what it
 * accepts from them (#525).
 *
 * Every field beyond `issuer`, `keys` and `algorithms` is a ceiling: it can
 * only narrow what an assertion from this issuer may obtain, never widen the
 * request, the client registration or the policy.
 *
 * An entry is **data**, so a registry can keep it in a store: every field
 * survives a JSON round trip, `expiresAt` revived as a `Date`. The one
 * exception is `keys.type: "key"`, a live key object for the in-process shape
 * `createJwtAssertionVerifier` builds — a store-backed registry holds `jwks`
 * (a one-key set is fine) or `jwks_uri` instead. How claims are *read* is code,
 * and code is the verifier's: `RegistryAssertionVerifierOptions.readersFor`. An entry is immutable
 * except for `expiresAt` — delete and re-add to change anything else, so the
 * audit trail of "what did we trust, and when" stays a list of adds and
 * removes.
 */
export interface AssertionIssuerEntry {
    /** The exact `iss` value. Matched by string equality, never by prefix. */
    readonly issuer: string;
    readonly keys: AssertionIssuerKeySource;
    /**
     * Signature algorithms accepted from this issuer, e.g. `["EdDSA"]`. Required
     * with no default: jose otherwise accepts anything the key can verify.
     */
    readonly algorithms: readonly string[];
    /**
     * `sub` values accepted from this issuer. Absent means any subject — the
     * Store still decides whom a handle resolves to (#301).
     */
    readonly allowedSubjects?: readonly string[];
    /**
     * Scopes an assertion from this issuer may obtain. The verification result
     * carries the intersection with the assertion's own `scope` claim (or this
     * list when the assertion names none) as its scope ceiling.
     */
    readonly allowedScopes?: readonly string[];
    /**
     * Audiences a token minted from this issuer's assertions may name. A
     * ceiling on the issued `aud` whatever chose it, and — with no
     * authenticated client — the source the client registration would
     * otherwise be (#520).
     */
    readonly allowedAudiences?: readonly string[];
    /**
     * Client ids permitted to present this issuer's assertions. Absent means
     * any presenter, an unauthenticated one included (RFC 7523 §3 makes client
     * authentication optional). A list admits those clients only; an
     * unauthenticated presenter is refused.
     */
    readonly allowedClients?: readonly string[];
    /**
     * After this instant the entry is refused. The only mutable field. A
     * registry over a store hands it back as a `Date`.
     */
    readonly expiresAt?: Date;
    /**
     * Which assertion profile this issuer mints (#526).
     *
     * - `"rfc7523"` (default): the plain RFC 7523 §2.1 assertion — `iss`,
     *   `sub`, `aud` (any of the verifier's audiences), `exp`; a device
     *   credential.
     * - `"id-jag"`: the Identity Assertion JWT Authorization Grant an
     *   enterprise IdP mints for a client. `typ` `oauth-id-jag+jwt`, `aud`
     *   exactly this server's issuer identifier, `client_id` naming the
     *   authenticated presenter, `jti` accepted once, and `scope` / `resource`
     *   carried as claims. Needs `issuerIdentifier` and `replaySeenSet` on the
     *   verifier.
     */
    readonly profile?: "rfc7523" | "id-jag";
    /** Clock skew for `exp` / `nbf`, in seconds. Default 60. */
    readonly clockToleranceSeconds?: number;
}
/**
 * The lookup the registry verifier performs before any signature work: is
 * this `iss` one we trust, and on what terms?
 *
 * Throwing means the registry could not answer — a backing store being down —
 * and is surfaced as `503`, like every other outage on the verification path.
 * `null` is the answer for an issuer nobody registered.
 */
export interface AssertionIssuerRegistry {
    readonly kind: string;
    findIssuer(issuer: string): Promise<AssertionIssuerEntry | null>;
}
/**
 * The admin surface (#525): add, list, remove, and the one permitted edit.
 * Entries are otherwise immutable so that the history of what was trusted
 * is the history of adds and removes.
 *
 * An edit reaches the registry it is made on. For the memory registry that is
 * one process: see {@link createMemoryAssertionIssuerRegistry}.
 */
export interface MutableAssertionIssuerRegistry extends AssertionIssuerRegistry {
    /** Refuses a duplicate `issuer` and a malformed entry. */
    add(entry: AssertionIssuerEntry): Promise<void>;
    list(): Promise<readonly AssertionIssuerEntry[]>;
    /** @returns whether an entry was removed. */
    remove(issuer: string): Promise<boolean>;
    /** @returns whether an entry was updated. */
    setExpiresAt(issuer: string, expiresAt: Date | undefined): Promise<boolean>;
}
/**
 * Validate an entry the way boot validates configuration: loudly, naming the
 * field. Shared by the memory registry and by anyone building an entry ahead
 * of registering it.
 */
export declare function checkAssertionIssuerEntry(entry: AssertionIssuerEntry): void;
/**
 * The in-memory registry: entries supplied at composition, mutable through
 * the admin surface, gone at restart. A deployment that registers issuers at
 * runtime and needs them to survive a restart implements
 * {@link AssertionIssuerRegistry} over its own store.
 *
 * **Replicas.** Entries supplied here are the same on every replica that runs
 * the same composition, so a static registry is replica-safe. The admin
 * surface is not: `add`, `remove` and `setExpiresAt` change this process only,
 * and an issuer revoked on the replica that took the call stays trusted on
 * every other. A restart does not converge them: it rebuilds the registry from
 * the composition's entries, restoring the revoked issuer on that replica too.
 * `deployment.mode = "multi"` cannot refuse it —
 * the registry sits inside the `assertionVerifier` a composition hands in, not
 * on a module manifest the boot guard reads — so a multi-replica deployment
 * changes the entry list by redeploying, or keeps it in a shared store.
 */
export declare function createMemoryAssertionIssuerRegistry(entries?: readonly AssertionIssuerEntry[]): MutableAssertionIssuerRegistry;
//# sourceMappingURL=issuerRegistry.d.mts.map