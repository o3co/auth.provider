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

/*
 * `federationTokenSnapshot`: the one reading of an upstream token response an
 * adapter puts on a `FederationProfile` or answers a refresh with. Every
 * bundled adapter reads its token endpoint through it, so a lifetime, a type
 * or a scope means the same whichever IdP issued the token. No state.
 */

/**
 * An RFC 6749 §5.1 token response as the adapter's OAuth library hands it
 * over after validating it: `access_token` and `token_type` are strings,
 * `expires_in` a number and `scope` a string when present. openid-client's
 * answer is this shape — oauth4webapi refuses a non-string scope, lower-cases
 * `token_type`, and applies `parseFloat` to an `expires_in` that is not a
 * number (`"1000seconds"` reads as 1000, `[3600, 7200]` as 3600) before the
 * adapter sees it. Declared here so that no vendor type reaches this contract.
 */
export interface FederationTokenResponse {
	readonly access_token: string;
	readonly token_type: string;
	readonly expires_in?: number;
	readonly refresh_token?: string;
	readonly id_token?: string;
	readonly scope?: string;
}

/**
 * The token fields of a `FederationProfile` or a `RefreshedTokens`, as one
 * response states them. A type alias rather than an interface so that it is
 * assignable to `RefreshedTokens`, whose extension slot is an index signature.
 */
export type FederationTokenSnapshot = {
	readonly accessToken: string;
	readonly refreshToken?: string;
	readonly idToken?: string;
	/** `obtainedAt + expiresIn`, or `null` when the response stated no lifetime. */
	readonly expiresAt: Date | null;
	/** `expires_in` as the library read it, or `null` when the response carried none. */
	readonly expiresIn: number | null;
	/** Present exactly when the response carried a `scope` — an empty one included, `""` for a non-string. */
	readonly scope?: string;
	readonly tokenType: string;
};

const nonEmpty = (value: string | undefined): value is string =>
	typeof value === "string" && value.length > 0;

/**
 * Read a token response the way every adapter does.
 *
 * - **Lifetime.** `expires_in` as the library read it, and `expiresAt` dated
 *   from `obtainedAt`: when the library handed the answer over, after any
 *   id_token verification and before UserInfo. An absent `expires_in` is
 *   `null` on both fields; no lifetime is invented for it. (The grant reader
 *   in `federation-oidc` reads the raw body instead and refuses a non-number
 *   lifetime, because grant eligibility judges the issued lifetime against an
 *   operator maximum; a login's expiry only says when a refresh is due.)
 * - **Scope.** Present exactly when the response carried one, an empty one
 *   included, and `""` for a non-string: the session route reads an absent
 *   scope as "as requested" (RFC 6749 §3.3), so an unusable answer must not
 *   flatten into silence.
 * - **Refresh token and id_token** only when non-empty strings; an empty one
 *   is not a credential.
 * - **Token type** as the library reported it, which
 *   `POST /oauth/federation/:name/token` judges before handing a token on.
 */
export function federationTokenSnapshot(
	response: FederationTokenResponse,
	obtainedAt: number = Date.now(),
): FederationTokenSnapshot {
	const expiresIn = typeof response.expires_in === "number" ? response.expires_in : null;
	return {
		accessToken: response.access_token,
		...(nonEmpty(response.refresh_token) ? { refreshToken: response.refresh_token } : {}),
		...(nonEmpty(response.id_token) ? { idToken: response.id_token } : {}),
		expiresAt: expiresIn === null ? null : new Date(obtainedAt + expiresIn * 1000),
		expiresIn,
		...(response.scope === undefined
			? {}
			: { scope: typeof response.scope === "string" ? response.scope : "" }),
		tokenType: response.token_type,
	};
}
