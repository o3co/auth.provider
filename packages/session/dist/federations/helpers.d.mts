import type { FederationResult } from "./types.mjs";
/**
 * Shared config shape for federation providers that support redirect validation
 * and callback redirect resolution.
 */
export interface RedirectConfig {
    sessionDomain?: string;
    authCallbackUrl?: string;
    clientUrl?: string;
}
/**
 * Validates that the given URL is acceptable as a post-login redirect target.
 *
 * Rules:
 * - Must be ≤ 2048 characters.
 * - Must be a valid absolute URL with http: or https: scheme.
 * - If `sessionDomain` is configured, the URL hostname must match or be a
 *   subdomain of the normalised domain (leading dot stripped).
 */
export declare function validateRedirect(url: string, config: Pick<RedirectConfig, "sessionDomain">): FederationResult<void>;
/**
 * Resolves the post-login redirect URL from the session state.
 *
 * - If session has `redirectTo` and `authCallbackUrl` is configured, returns
 *   `authCallbackUrl?redirect_to=<encoded redirectTo>`.
 * - If session has `redirectTo` but `authCallbackUrl` is absent, returns a
 *   misconfiguration error.
 * - If no `redirectTo`, returns `clientUrl` (or a misconfiguration error when
 *   `clientUrl` is also absent).
 */
export declare function resolveCallbackRedirect(session: {
    redirectTo?: string;
}, config: Pick<RedirectConfig, "authCallbackUrl" | "clientUrl">): FederationResult<string>;
//# sourceMappingURL=helpers.d.mts.map