/**
 * The test double of the `sessionCookiePolicy` slot.
 * `createTestSessionCookiePolicy` answers the fixture configuration's cookie
 * with any attribute replaced; it checks nothing. The contract suite is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */
import type { SessionCookiePolicy } from "../../browser-session/types.mjs";
/**
 * The fixture configuration's session cookie — `__Host-auth.session`,
 * secure, `lax`, host-only, one hour — with `overrides` applied, frozen.
 */
export declare function createTestSessionCookiePolicy(overrides?: Partial<SessionCookiePolicy>): SessionCookiePolicy;
//# sourceMappingURL=sessionCookiePolicy.d.mts.map