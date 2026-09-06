import type { ProviderDeps } from "@o3co/auth-provider-core";
import type { RedirectConfig } from "./helpers.mjs";
import type { FederationResult } from "./types.mjs";
/**
 * Consumer-facing redirect URL validation and callback redirect resolution.
 *
 * Distinct from `FederationProvider` (upstream IdP protocol) — this interface
 * is the consumer's allowed-redirect-URL policy for a named federation.
 * Consumers can replace this independently of the IdP integration.
 *
 * Per A5 §5.2.
 */
export interface FederationRedirectPolicy {
    /**
     * URL-pattern validation for a consumer-supplied `redirect_to`.
     *
     * Returns `{ ok: true }` when the URL passes the policy's allowlist;
     * otherwise returns a `FederationResult` failure with HTTP status code,
     * OAuth error code, and error description suitable for direct response.
     *
     * Same behavior contract as the v0.4.x `FederationProvider.validateRedirect`
     * method that this replaces.
     */
    validateRedirect(url: string): FederationResult<void>;
    /**
     * Resolve the post-callback redirect URL from the session's `redirectTo`.
     *
     * Returns `{ ok: true, value: string }` with the resolved redirect URL on
     * success; otherwise returns a `FederationResult` failure.
     *
     * Same behavior contract as the v0.4.x `FederationProvider.resolveCallbackRedirect`
     * method that this replaces.
     */
    resolveCallbackRedirect(session: {
        readonly redirectTo?: string;
    }): FederationResult<string>;
}
/**
 * Per-contribution factory type for `federationRedirectPolicies` contributions.
 * Follows the A2-α §4.1 contribution-factory pattern.
 *
 * Per A5 §5.3.
 */
export type FederationRedirectPolicyFactory<Deps = ProviderDeps<never, never>> = (deps: Deps) => FederationRedirectPolicy;
/**
 * Config slice consumed by the redirect policy.
 *
 * This is the v0.4.x helper-facing shape (see `helpers.mts`):
 *   - `sessionDomain`: cookie domain; redirect targets must match or be
 *     subdomains of this hostname.
 *   - `authCallbackUrl`: post-callback bridge endpoint that wraps a
 *     consumer-supplied `redirect_to` query parameter.
 *   - `clientUrl`: fallback redirect when session has no `redirectTo`.
 *
 * A `Pick<RedirectConfig, ...>` projection limits the policy to the
 * fields it actually consumes. A5 does NOT invent new field names.
 *
 * Per A5 §9.
 */
export type FederationRedirectPolicyConfig = Pick<RedirectConfig, "sessionDomain" | "authCallbackUrl" | "clientUrl">;
/**
 * Default `FederationRedirectPolicy` factory that preserves v0.4.x
 * `validateRedirect` / `resolveCallbackRedirect` behavior bit-identically
 * by delegating to the same underlying helpers in `helpers.mts`.
 *
 * Provider configs (`GoogleProviderConfig`, `GithubProviderConfig`) include
 * the three required fields, so passing the full provider config is valid
 * via structural assignability.
 *
 * Per A5 §9.
 */
export declare function createFederationRedirectPolicy(config: FederationRedirectPolicyConfig): FederationRedirectPolicy;
//# sourceMappingURL=redirect-policy.d.mts.map