import type { EffectiveFederationGrantStatus, FederationGrant, FederationGrantConnection } from "./types.mjs";
/**
 * Whether a subject's revocation boundary covers an instant (#593, D13): a
 * grant's consent against the grants boundary, and a session's authentication
 * against the sessions boundary (D7).
 *
 * For a grant it is the consent that is compared. Not a token's `iat`: a token
 * minted from a surviving grant is always fresh. And not `authorizedAt`: the
 * consent precedes the callback by up to ten minutes, and a callback that
 * lands just after the boundary must not hide a consent given before it.
 *
 * Inclusive, with the allowance the token check in `jwt/verify.mts` gives the
 * same boundary (`subjectRevocationSkewMs`, one second) — and not the
 * five-minute `clockSkewMs`, which would refuse the re-login a revocation
 * sends the user to. A negative allowance reads as none. `null` is a subject
 * with no boundary in force.
 *
 * A value that cannot be compared is thrown, and answered neither way. "Not
 * covered" would switch the backstop off — for every grant at once, if the
 * allowance is what is wrong, since `Math.max(0, NaN)` is NaN. "Covered"
 * would revoke durably because of a corrupt value. It is an outage, and the
 * caller answers 503, as `verifyJwt` does for a boundary it cannot read.
 */
export declare function coveredByRevocationBoundary(instant: Date, boundary: Date | null, skewMs: number): boolean;
export interface EffectiveFederationGrantStatusContext {
    readonly now: Date;
    /**
     * The connection as it is configured now; `undefined` when the operator has
     * removed it. That is reported as `connection_not_configured`, after every
     * terminal fact and before anything that needs a connection to compare with.
     */
    readonly connection: FederationGrantConnection | undefined;
    /** `federationGrants.maxExpiresIn` as it is configured now, in milliseconds. */
    readonly maxExpiresInMs: number;
    /** The subject's grants boundary; `null` when none is in force. */
    readonly grantsBoundary: Date | null;
    readonly revocationSkewMs: number;
    /**
     * Whether the sealed credential authenticates under the current key ring.
     * Only consulted for a grant that is stored as `active`: every other stored
     * state has had its credential deleted (D2), and an `active` grant with no
     * credential record at all is `"unreadable"`.
     */
    readonly credentials: "ok" | "unreadable";
}
/**
 * What a caller is told about a grant (#593, D1). Computed on every read and
 * never persisted: undoing a configuration change, or restoring a key,
 * restores the grant. Only a revocation and an upstream `invalid_grant` are
 * facts about the grant itself, and only those are stored.
 *
 * The order is from what cannot be undone to what can, so that a client is
 * never sent to a remedy that cannot work:
 *
 * 1. a stored revocation;
 * 2. the backstop, before expiry, so that a revocation which never reached the
 *    record is not reported as a mere expiry — and for a grant that already
 *    needs the user too, since the boundary ends that one as well. Not for a
 *    `pending` grant: it has no consent to date, and D7 already demands a
 *    session that authenticated after the boundary;
 * 3. expiry, the terminal bound first (`federationGrantExpiryState`);
 * 3a. a connection that is no longer configured. Putting the entry back
 *    restores the grant, so it comes after what cannot be undone — a
 *    configuration remedy must not be offered for a grant that is over — and
 *    it is not a changed identity, which removing an entry does not establish;
 * 4. a changed upstream identity, which no reauthorization can mend — before
 *    the stored `invalid_grant`, because `/reauthorize` refuses such a grant;
 * 5. what a reauthorization does mend: a stored `invalid_grant`, a changed
 *    connection, a credential that does not open — and an upstream that asked
 *    for the user (#616): a refusal stamped with an interaction code, read for
 *    as long as it stands, since time mends nothing there;
 * 6. a grant that cannot yield a token: a `maxAccessTokenLifetime` no token
 *    can satisfy — known without asking the upstream, and named as the reason
 *    whatever an older marker says, because that is what `/token` answers —
 *    and then an upstream that stopped issuing eligible tokens, for as long as
 *    the marker stands. After what a reauthorization mends, since a
 *    reauthorization clears the marker as well.
 *
 * This is the order D10's steps are reported in, which is not the order the
 * ADR lists them: it puts the backstop before expiry.
 *
 * A key that is missing from the ring is not a status. It is an outage: the
 * caller passes `"unreadable"` for it and answers 503 where this would say
 * `credential_unreadable` — and only there, so that the outage masks nothing
 * that is reported ahead of it, none of which needs a credential. So is a
 * boundary that cannot be compared: `coveredByRevocationBoundary` throws.
 */
export declare function effectiveFederationGrantStatus(grant: FederationGrant, context: EffectiveFederationGrantStatusContext): EffectiveFederationGrantStatus;
//# sourceMappingURL=effective-status.d.mts.map