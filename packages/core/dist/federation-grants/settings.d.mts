import { type FederationGrantRetrievalLimits } from "./retrieve.mjs";
/**
 * The defaults `config/reference.conf` ships, in the units it writes them.
 *
 * Exported because a hand-built configuration never passes through that file,
 * and a second copy of these numbers inside a module would be the one that is
 * forgotten. `settings.test.mts` reads the block back out of `reference.conf`
 * and compares it to this, so the two cannot drift.
 */
export declare const FEDERATION_GRANT_SETTING_DEFAULTS: {
    /** Seconds. Thirty days: what a new grant gets (D3), reserved for acquisition. */
    readonly defaultExpiresIn: 2592000;
    /**
     * Seconds. Thirty days, deliberately NOT the one-year ceiling the code
     * enforces above it: a security-relevant maximum whose default is the
     * highest value permitted is the wrong way round, and an operator raises
     * it on purpose.
     */
    readonly maxExpiresIn: 2592000;
    /** Seconds. A token with no more life than this is refreshed (D10). */
    readonly refreshBuffer: 30;
    /** Seconds. The ceiling on how long a failing upstream is not asked (D12). */
    readonly ineligibleRetryAfter: 300;
    /** Seconds. How long a row of failures is honoured for. */
    readonly refreshFailureBackoff: 30;
    /** Milliseconds. The soft deadline: how long a caller waits. */
    readonly upstreamTimeoutMs: 10000;
    /** Milliseconds. The hard deadline: where the upstream request is aborted. */
    readonly upstreamHardTimeoutMs: 25000;
    /** Milliseconds. The refresh lock has no renewal, so it must outlive a refresh. */
    readonly refreshLockTtlMs: 30000;
    /** Milliseconds. How long a call waits for another replica's refresh. */
    readonly lockWaitMs: 5000;
    /** Milliseconds. How long a refresh keeps trying to write down what it got. */
    readonly persistRetryBudgetMs: 3000;
    /** Seconds. How long a record answers past the end of what it authorized (D16). */
    readonly tombstoneRetention: 2592000;
};
/**
 * The lifetimes acquisition offers, from the configuration an operator wrote
 * (D3): what a new grant gets, and the most a client may ask for.
 *
 * `defaultExpiresIn` had been in the schema and in `reference.conf` since slice
 * 4, and nothing read it — this is its reader.
 *
 * A default above the maximum is refused rather than clamped. Lodging clamps a
 * CLIENT's request, and says so in the lifetime it answers with; an operator's
 * default that the maximum silently cut down would give every grant a lifetime
 * nobody wrote anywhere.
 */
export declare function resolveFederationGrantAcquisitionLimits(config: unknown): {
    readonly defaultLifetimeMs: number;
    readonly maxLifetimeMs: number;
};
/**
 * The limits `retrieveFederationGrantToken` takes, from the configuration an
 * operator wrote.
 *
 * Refuses rather than repairs. `assertFederationGrantRetrievalLimits` carries
 * the relationships between the timers — soft within hard, the lock outliving
 * a refresh and its persistence, the backoff inside the retry interval — and
 * is called here so that a hand-built configuration meets them too (#448).
 * What it does not carry is the grant lifetime ceiling, because that is a
 * lifetime and not a timer, so this checks it.
 */
export declare function resolveFederationGrantRetrievalLimits(config: unknown): FederationGrantRetrievalLimits;
/**
 * `federationGrants.allowKeepOnSubjectRevocation`, from the configuration an
 * operator wrote (D13).
 *
 * Read on its own rather than through {@link FEDERATION_GRANT_SETTING_DEFAULTS}
 * and `setting`: those carry a unit and a maximum, and every one of their
 * checks is about a duration. A boolean in that object would be a value whose
 * key ends in neither `Ms` nor a number, taking the wrong branch of each of
 * them.
 *
 * Refuses rather than repairs, for the reason the durations do — but the stake
 * here is the opposite direction: a value nobody can read must not become
 * `true`. `"false"`, `"0"` and an empty string are what HOCON substitutes an
 * unset `${?VAR}` chain as, and they mean what they say; anything else is
 * named.
 */
export declare function resolveFederationGrantKeepPolicy(config: unknown): boolean;
//# sourceMappingURL=settings.d.mts.map