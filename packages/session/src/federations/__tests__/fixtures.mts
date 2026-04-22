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

import type {
	EndSessionRequest,
	EndSessionResult,
	FederationProvider,
	SupportsLogout,
} from "../types.mjs";

/**
 * Test fixture: a minimal provider that implements only the FederationProvider contract.
 * Used to exercise the `supportsLogout(p) === false` path and as a starting shape
 * that external implementers can copy when writing a custom provider without the
 * logout capability.
 */
export function createTestBaseProvider(name: string): FederationProvider {
	return {
		name,
		scope: [],
		validateRedirect: () => ({ ok: true, value: undefined }),
		resolveCallbackRedirect: () => ({ ok: true, value: "/" }),
		buildAuthorizationUrl: () => new URL("https://example.com/authorize"),
		exchangeCode: async () => ({ issuer: "https://example.com", sub: "test-sub" }),
	};
}

/**
 * Test fixture: a minimal provider implementing the {@link SupportsLogout} capability.
 *
 * Reference implementation — built-in providers (Google / GitHub) do not implement
 * this capability because their IdPs do not expose an end-session endpoint.
 * External OSS users writing Microsoft / Auth0 / Okta integrations should mirror
 * the `endSession()` body below.
 */
export function createTestLogoutProvider(opts: {
	name: string;
	endSessionEndpoint: string;
}): FederationProvider & SupportsLogout {
	return {
		...createTestBaseProvider(opts.name),
		async endSession(req: EndSessionRequest): Promise<EndSessionResult> {
			const url = new URL(opts.endSessionEndpoint);
			if (req.idTokenHint) url.searchParams.set("id_token_hint", req.idTokenHint);
			if (req.postLogoutRedirectUri)
				url.searchParams.set("post_logout_redirect_uri", req.postLogoutRedirectUri);
			if (req.state) url.searchParams.set("state", req.state);
			return { url, method: "GET" };
		},
	};
}
