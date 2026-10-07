import type { OAuthTokenSettings } from "./types.mjs";
/** A token lifetime a slot names beyond the one core resolves from the configuration. */
export interface LifetimeBeyondConfiguration {
    /** The slot's member, as the contract names it. */
    readonly member: "accessTokenLifetime.maxExpiresIn" | "refreshTokenExpiresIn";
    /** The configuration key core resolves the lifetime from. */
    readonly configKey: "oauth.accessToken.maxExpiresIn" | "oauth.refreshToken.expiresIn";
    /** The slot's lifetime, in seconds. */
    readonly slotSeconds: number;
    /** The lifetime core resolves from the configuration, in seconds. */
    readonly configurationSeconds: number;
}
/**
 * The first token lifetime `settings` names beyond the one core resolves
 * from `config` (access-token max, then refresh-token), or `undefined`. A
 * non-number member is not compared; one whose read throws counts as none.
 * Each configured lifetime sizes a revoking record kept by a reader that
 * cannot read the slot: the access-token maximum, how long the refresh-token
 * family modules remember a revoked family (a family's own expiry follows the
 * slot); the refresh-token lifetime, how long the session lifecycle keeps a
 * closing session's record. A longer slot lifetime would mint a token that
 * outlives that record.
 * The resolver refuses a configuration that resolves no lifetime, naming
 * the key. Internal to core.
 */
export declare function lifetimeBeyondConfiguration(settings: object, config: unknown): LifetimeBeyondConfiguration | undefined;
/**
 * The refusal of a lifetime beyond the configuration's: the member, both
 * values, the configuration key, and why. `from` names where the slot came
 * from, when the caller knows.
 */
export declare function lifetimeBeyondConfigurationMessage(found: LifetimeBeyondConfiguration, from?: string): string;
/**
 * The `oauthTokenSettings` a composition holds, as a snapshot frozen at
 * every level: each member a reader reads, read from `value` exactly once
 * and held to its contract rule. What is validated is what is answered: a
 * getter that changes its answer, or a host that changes its object later,
 * changes nothing a reader holds. Members no reader reads are neither
 * checked nor carried.
 *
 * This form needs no configuration: it holds the lifetimes to their
 * contract rule alone. Bounding them by the ones core resolves from the
 * configuration is boot's, for every slot a composition holds, whoever
 * fills it: as the value enters the component map (stage 3, a host map's
 * also at stage 1), boot replaces it with the snapshot of the
 * two-argument form, so every reader within `createApp` is handed a frozen
 * value already within them. A caller outside boot — a grant or handler
 * built by hand from a value that never went through `createApp` — owns
 * the bound, and holds the value with the two-argument form.
 *
 * @throws RangeError naming the first member that does not hold or whose
 *   read throws, or the slot when it holds no settings object.
 */
export declare function checkOAuthTokenSettings(value: unknown): OAuthTokenSettings;
/**
 * The check above, and no lifetime longer than the one core resolves from
 * `config` (both values named when one is): what boot holds every slot to,
 * and what a caller outside boot holds a value to. Transitional for a
 * reader within `createApp`, which holds the slot boot checked with the
 * one-argument form instead. Passing `config` selects this form even when
 * it is `undefined`, which refuses.
 */
export declare function checkOAuthTokenSettings(value: unknown, config: unknown): OAuthTokenSettings;
//# sourceMappingURL=check.d.mts.map