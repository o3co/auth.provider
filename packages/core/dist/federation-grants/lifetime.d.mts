import type { FederationGrantExpiredReason } from "./types.mjs";
/**
 * The longest a federation grant can live: one year (#593, D3).
 *
 * The config schema caps `federationGrants.maxExpiresIn` at the same value,
 * but a hand-built config bypasses a schema (#448), and D13's revocation
 * boundary is retained for exactly this long. So the ceiling is a constant of
 * the domain, and both the lifetime an intent gets and the write that
 * activates a grant check it.
 */
export declare const FEDERATION_GRANT_LIFETIME_CEILING_MS = 31536000000;
/**
 * The lifetime a grant gets when its intent is lodged.
 *
 * A request above the maximum is clamped, not rejected, as the access-token
 * lifetime of a token exchange is: the caller learns the value that applied
 * from the response. The default is clamped too, and everything is clamped to
 * the ceiling — here, and not only at `activate`, so that a lifetime the write
 * would refuse is never offered to a user who then consents upstream for
 * nothing.
 */
export declare function resolveFederationGrantLifetimeMs(limits: {
    readonly requestedMs?: number;
    readonly defaultMs: number;
    readonly maxMs: number;
}): number;
/**
 * A grant's expiry counts from the consent, not from the callback that
 * follows it by up to ten minutes. D13's proof that no grant outlives its
 * revocation boundary rests on `expiresAt − consent.at` being within the
 * ceiling, so both are measured from the same instant.
 */
export declare function federationGrantExpiresAt(consentAt: Date, lifetimeMs: number): Date;
/**
 * The guard `activate` applies to the fields it is about to write (D2). A date
 * that is not a date fails it: `NaN > 0` is false.
 */
export declare function withinFederationGrantLifetimeCeiling(consentAt: Date, expiresAt: Date): boolean;
interface ExpiryFields {
    readonly consent: {
        readonly at: Date;
    };
    readonly expiresAt: Date;
}
/**
 * When a grant stops yielding tokens: the consented expiry, or the operator's
 * current maximum counted from the consent, whichever comes first. Lowering
 * the maximum shortens existing grants, which is what lowering it means.
 *
 * Nothing that is persisted — a key's TTL, the revocation boundary — may be
 * computed from this. A maximum that can be raised again cannot be the basis
 * of a guarantee; persisted horizons use the stored `expiresAt` or the ceiling.
 */
export declare function federationGrantEffectiveExpiry(grant: ExpiryFields, maxMs: number): Date;
/**
 * Whether a grant has expired, and which bound ended it. The consented
 * lifetime is terminal: new consent means a new grant. The operator's maximum
 * is not — a grant that reads as expired only because the maximum was lowered
 * yields tokens again if it is raised, always within what the user consented
 * to. When both have passed, the terminal reason is the one reported.
 *
 * Each test is written as "is it still before the bound?" and negated. Every
 * comparison with NaN is false, so the other way round — "has the bound
 * passed?" — would answer no for a corrupt date or a maximum that is not a
 * number, and the grant would read as live for ever.
 */
export declare function federationGrantExpiryState(grant: ExpiryFields, now: Date, maxMs: number): "live" | FederationGrantExpiredReason;
export {};
//# sourceMappingURL=lifetime.d.mts.map