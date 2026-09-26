import { type JWTPayload } from "jose";
import type { ReplaySeenSet } from "../replay-seen-set/types.mjs";
import type { AssertionIssuerEntry, AssertionIssuerRegistry } from "./issuerRegistry.mjs";
import type { AssertionVerifier } from "./types.mjs";
/** The `typ` an Identity Assertion JWT Authorization Grant MUST carry (ID-JAG §3). */
export declare const ID_JAG_TYP = "oauth-id-jag+jwt";
export interface RegistryAssertionVerifierOptions {
    readonly registry: AssertionIssuerRegistry;
    /**
     * What an RFC 7523 assertion's `aud` must name — this authorization server.
     * RFC 7523 §3 requires the AS to reject an assertion not addressed to it,
     * and the reason is concrete: without it, an assertion minted for a
     * *different* service is replayable here. Several values are accepted so a
     * deployment can name both its issuer identifier and its token endpoint URL.
     */
    readonly audience: string | readonly string[];
    /**
     * This authorization server's issuer identifier (RFC 8414) — the one and
     * only `aud` an ID-JAG may name (#526). Required by any entry whose
     * `profile` is `"id-jag"`; the token endpoint URL is not an alias there.
     */
    readonly issuerIdentifier?: string;
    /**
     * Where ID-JAG `jti` values are recorded so each assertion is accepted once
     * (#526). Keyed per issuer, expiring with the assertion. Required by any
     * `"id-jag"` entry; an outage of the store throws, so the grant answers
     * `503` rather than accepting a replay.
     */
    readonly replaySeenSet?: ReplaySeenSet;
    /** Adapter kind, for logs and boot diagnostics. Default `"jwt-registry"`. */
    readonly kind?: string;
    /** The fetch a `jwks_uri` entry's key set uses. An egress proxy, or a test seam. */
    readonly fetch?: typeof fetch;
    /**
     * How an entry's claims are read — code, so it lives here rather than on
     * the entry a store holds. Called per verification with the entry found;
     * `undefined`, or an absent reader, keeps the default: a non-empty `sub`
     * (or `<iss>#<sub>` / `<iss>#<tenant>#<sub>` for an ID-JAG) and a
     * space-delimited `scope`.
     *
     * It runs for every entry, ID-JAG ones included. With several issuers
     * whose `sub` values may collide, namespace the handle for the entries that
     * need it and return `undefined` for the rest, and refuse a missing or empty
     * `sub` rather than namespacing it — the Store receives the handle alone:
     *
     * ```ts
     * readersFor: (entry) =>
     *   entry.profile === "id-jag"
     *     ? undefined // keeps <iss>#<tenant>#<sub>
     *     : { readSubjectHandle: (c) =>
     *         typeof c.sub === "string" && c.sub.length > 0 ? `${entry.issuer}#${c.sub}` : null },
     * ```
     */
    readonly readersFor?: (entry: AssertionIssuerEntry) => AssertionClaimReaders | undefined;
}
/** How a verifier reads the subject handle and the scope ceiling from an issuer's claims. */
export interface AssertionClaimReaders {
    /** The handle the Store resolves; `null` refuses the assertion. */
    readonly readSubjectHandle?: (claims: JWTPayload) => string | null;
    /** The scope the assertion claims, before the entry's ceiling applies. */
    readonly readScope?: (claims: JWTPayload) => readonly string[] | undefined;
}
/**
 * The {@link AssertionVerifier} over a trust registry (#525): "we trust these
 * N issuers, each with their own keys and terms", where
 * `createJwtAssertionVerifier` was "this one key, this one issuer".
 *
 * ## Order of checks, and why
 *
 * 1. Decode the claims without verifying, read `iss`, and look it up. An
 *    issuer nobody registered is refused **before any signature work**: no
 *    key is fetched, no signature is checked. This is what keeps an
 *    unregistered issuer from costing a JWKS fetch per probe, and what makes
 *    "signed by A, claiming to be B" fail on B's keys rather than A's.
 * 2. The entry must not have expired, and the presenting client must be one
 *    the entry admits (`allowedClients`; an unauthenticated presenter passes
 *    only when the entry names no list).
 * 3. Signature, `iss`, `aud`, `exp` (mandatory, RFC 7523 §3 item 4), `nbf` /
 *    `iat` when present, against the entry's keys and algorithms.
 * 4. `sub` must be one the entry admits (`allowedSubjects`), and the handle
 *    reader must find a handle.
 * 5. The result carries the entry's ceilings: the scope claim intersected
 *    with `allowedScopes`, and `allowedAudiences` as the audience ceiling.
 *
 * ## The ID-JAG profile (#526)
 *
 * An entry with `profile: "id-jag"` accepts the Identity Assertion JWT
 * Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant) —
 * what an enterprise IdP mints for a client so a resource's authorization
 * server can issue it a token. On top of the checks above, in step 3 and
 * after it:
 *
 * - the JWT header `typ` MUST be `oauth-id-jag+jwt` (§3, RFC 8725 §3.11);
 * - `aud` MUST be this server's issuer identifier — `issuerIdentifier`,
 *   never the token endpoint URL — as one string or a one-element array;
 * - `client_id` MUST name the client that authenticated at the token
 *   endpoint; an unauthenticated presenter is refused — client
 *   authentication is required for this grant;
 * - `jti`, `iat` and `sub` are required, and each `jti` is accepted **once**
 *   for the assertion's lifetime, recorded in `replaySeenSet` per issuer;
 * - `scope` and `resource` travel as claims, not request parameters: the
 *   scope ceiling is the claim intersected with `allowedScopes`, and the
 *   audience ceiling is the `resource` claim intersected with
 *   `allowedAudiences` (a resource the entry does not admit is refused). The
 *   grant then bounds both by the client's registration.
 * - the handle is `<iss>#<sub>` (or `<iss>#<tenant>#<sub>`): `sub` is unique
 *   only within its issuer, and resolving it to a local principal stays
 *   with the Store — an unlinked one is refused there.
 *
 * Every refusal is the same `null`. Distinguishing them would let a caller
 * probe for which issuers are registered or which subjects are admitted.
 * Replay within `exp` is detected for ID-JAG only; a plain RFC 7523 issuer
 * should mint short-lived assertions.
 */
export declare function createRegistryAssertionVerifier(options: RegistryAssertionVerifierOptions): AssertionVerifier;
//# sourceMappingURL=registryAssertionVerifier.d.mts.map