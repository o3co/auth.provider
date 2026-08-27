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

import type { FederationResult } from "./types.mjs";

/**
 * Shared config shape for federation providers that support redirect validation
 * and callback redirect resolution.
 */
export interface RedirectConfig {
	/**
	 * The exact redirect targets a consumer-supplied `redirect_to` may name.
	 *
	 * Read by `createFederationRedirectPolicy` (`redirect-policy.mts`), which
	 * owns the matching rules and the fail-closed behaviour when this is absent
	 * or empty. `validateRedirect` used to live here and derived its answer from
	 * `sessionDomain` alone, which meant an unset `sessionDomain` accepted every
	 * http(s) URL on earth (#278); it was removed rather than tightened so no
	 * caller can reach the permissive shape.
	 */
	redirectAllowlist?: readonly string[];
	sessionDomain?: string;
	authCallbackUrl?: string;
	clientUrl?: string;
}

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
export function resolveCallbackRedirect(
	session: { redirectTo?: string },
	config: Pick<RedirectConfig, "authCallbackUrl" | "clientUrl">,
): FederationResult<string> {
	const authCallbackUrl = config.authCallbackUrl;
	if (session.redirectTo && authCallbackUrl) {
		return {
			ok: true,
			value: `${authCallbackUrl}?redirect_to=${encodeURIComponent(session.redirectTo)}`,
		};
	}

	if (session.redirectTo && !authCallbackUrl) {
		return {
			ok: false,
			status: 500,
			error: "misconfiguration",
			errorDescription: "authCallback URL not configured but redirect_to was requested",
		};
	}

	const clientUrl = config.clientUrl;
	if (!clientUrl) {
		return {
			ok: false,
			status: 500,
			error: "misconfiguration",
			errorDescription: "client URL not configured",
		};
	}

	return { ok: true, value: clientUrl };
}
