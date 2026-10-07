/**
 * The one precedence every bundled limiter takes a key's budget by, so one
 * configuration is one budget whichever limiter is mounted.
 */
import type { RateLimitSpec } from "./types.mjs";
export interface RateLimitBudgetLookupOptions {
    /** What an operator declared on this limiter, by prefix. */
    readonly limits?: Readonly<Record<string, RateLimitSpec>>;
    /** What a key under a prefix `limits` does not name is limited by. */
    readonly defaultLimit: RateLimitSpec;
}
/** The prefix a key is limited under, and the budget in force for it. */
export interface RateLimitBudget {
    /** The key up to its first `:`, or the whole key when it has none. */
    readonly prefix: string;
    readonly spec: RateLimitSpec;
}
/** A key's budget, and the default it falls to. */
export interface RateLimitBudgetLookup {
    (key: string): RateLimitBudget;
    /** `defaultLimit` as it was checked, frozen. */
    readonly defaultLimit: RateLimitSpec;
}
/**
 * A key's budget: the limiter's own `limits` entry for its prefix, else
 * `defaultLimit` (never no limit). `limits` and `defaultLimit` are each read
 * once into a frozen copy, refused, naming `who`, unless usable, and held as
 * checked, so no spec a lookup hands out can change.
 */
export declare function createRateLimitBudgetLookup(who: string, options: RateLimitBudgetLookupOptions): RateLimitBudgetLookup;
//# sourceMappingURL=budgetLookup.d.mts.map