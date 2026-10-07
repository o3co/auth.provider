import type { CsrfGuard, SessionCookiePolicy } from "../../browser-session/types.mjs";
export interface TestCsrfGuardOptions {
    /** Origins other than the request's own a request may come from without a token. */
    readonly trustedOrigins?: readonly string[];
    /** The session cookie the guard stands beside: its token cookie is named from it and shares its attributes. The fixture's by default. */
    readonly sessionCookie?: SessionCookiePolicy;
    /** The clock, in epoch milliseconds, tokens are minted and judged by. */
    readonly now?: () => number;
}
/**
 * A `CsrfGuard` for tests that keeps the contract: the `Origin` / `Referer`
 * rule against the request's own origin and `trustedOrigins`, the
 * navigation rule, and a double-submit token signed with a key drawn when
 * it is built, valid for two hours by `now`, set in a cookie named from the
 * session cookie's (`<name>.csrf`) and sharing its attributes. Frozen.
 */
export declare function createTestCsrfGuard(options?: TestCsrfGuardOptions): CsrfGuard;
//# sourceMappingURL=csrfGuard.d.mts.map