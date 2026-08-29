/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { ProviderDeps } from "@o3co/auth-provider-core";
import { createRedirectAllowlistValidator } from "../redirect-allowlist.mjs";
import type { RedirectConfig } from "./helpers.mjs";
import { resolveCallbackRedirect } from "./helpers.mjs";
import type { FederationResult } from "./types.mjs";

/**
 * The federation half of the redirect policy: the shared allowlist rule (see
 * `../redirect-allowlist.mjs`, which documents why it fails closed and why it
 * matches exactly) plus `resolveCallbackRedirect`, which is federation-specific.
 *
 * The rule itself moved to the package root in #405, when `POST /session/login`
 * turned out to have kept the pre-#278 "any absolute http(s) URL" branch — the
 * same vulnerability one route over, left behind because the rule had been
 * written down somewhere the login route had no reason to import from. The
 * public names below are re-exported unchanged so this module stays the
 * federation-facing home of the vocabulary.
 */

export type {
	RedirectAllowlistOptions,
	RedirectAllowlistValidator,
	RedirectRejection,
} from "../redirect-allowlist.mjs";
export {
	checkRedirectShape,
	createRedirectAllowlistValidator,
	describeRedirectRejection,
	isLoopbackHostname,
	MAX_REDIRECT_URL_LENGTH,
} from "../redirect-allowlist.mjs";

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
	 * Validation for a consumer-supplied `redirect_to`.
	 *
	 * Returns `{ ok: true }` when the URL passes the policy's allowlist;
	 * otherwise returns a `FederationResult` failure with HTTP status code,
	 * OAuth error code, and error description suitable for direct response.
	 *
	 * An implementation MUST fail closed: refuse everything it has not been
	 * told to permit. The default implementation below does; a replacement that
	 * accepts "any URL that parses" reopens #278.
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
	resolveCallbackRedirect(session: { readonly redirectTo?: string }): FederationResult<string>;
}

/**
 * Per-contribution factory type for `federationRedirectPolicies` contributions.
 * Follows the A2-α §4.1 contribution-factory pattern.
 *
 * Per A5 §5.3.
 */
export type FederationRedirectPolicyFactory<Deps = ProviderDeps<never, never>> = (
	deps: Deps,
) => FederationRedirectPolicy;

/**
 * Config slice consumed by the redirect policy.
 *
 *   - `redirectAllowlist`: the exact URLs a `redirect_to` may name. Absent or
 *     empty means *nothing* is accepted.
 *   - `sessionDomain`: cookie domain; every non-loopback allowlist entry must
 *     be inside it, checked when the policy is built.
 *   - `authCallbackUrl`: post-callback bridge endpoint that wraps a
 *     consumer-supplied `redirect_to` query parameter.
 *   - `clientUrl`: fallback redirect when session has no `redirectTo`.
 *
 * A `Pick<RedirectConfig, ...>` projection limits the policy to the fields it
 * actually consumes.
 */
export type FederationRedirectPolicyConfig = Pick<
	RedirectConfig,
	"redirectAllowlist" | "sessionDomain" | "authCallbackUrl" | "clientUrl"
>;

/**
 * Default `FederationRedirectPolicy` factory.
 *
 * Provider configs (`GoogleProviderConfig`, `GithubProviderConfig`) are
 * structurally assignable, so the full provider config can be passed.
 *
 * Throws when `redirectAllowlist` holds an entry that could never match. An
 * **absent** allowlist does not throw: a deployment that never accepts
 * `redirect_to` is correctly configured, and its refusal surfaces on the
 * request that actually asks for a redirect.
 */
export function createFederationRedirectPolicy(
	config: FederationRedirectPolicyConfig,
): FederationRedirectPolicy {
	// Defensive snapshot: detach from the caller's reference so post-construction
	// mutation of the supplied config (e.g. `config.sessionDomain = "evil.com"`
	// later) cannot retroactively change behaviour. The allowlist is copied into
	// a Set for the same reason — freezing the config object would still leave
	// the caller's array mutable through its own reference.
	const frozenConfig = Object.freeze({ ...config });
	const validator = createRedirectAllowlistValidator({
		redirectAllowlist: frozenConfig.redirectAllowlist,
		sessionDomain: frozenConfig.sessionDomain,
		factoryName: "createFederationRedirectPolicy",
	});

	return Object.freeze({
		validateRedirect(url: string): FederationResult<void> {
			return validator.validateRedirect(url);
		},
		resolveCallbackRedirect(session: { readonly redirectTo?: string }): FederationResult<string> {
			return resolveCallbackRedirect(session, frozenConfig);
		},
	});
}
