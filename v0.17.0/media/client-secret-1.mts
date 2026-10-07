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

/**
 * A federation's `client_secret`, either fixed or computed per token exchange.
 *
 * A string suits most IdPs and config files. Apple's secret is an ES256 JWT
 * the relying party signs, valid for at most six months, so a fixed value
 * would silently stop authenticating. The function form lets the adapter own
 * that lifecycle, including any caching, since only it knows when its secret
 * expires.
 */
export type FederationClientSecret = string | (() => string | Promise<string>);

/**
 * Resolve a {@link FederationClientSecret} to the string to present at the
 * token endpoint. Called once per token exchange and per refresh, never
 * memoised. An empty or non-string result throws here rather than coming back
 * from the IdP as an opaque `invalid_client`.
 */
export const resolveClientSecret = async (secret: FederationClientSecret): Promise<string> => {
	if (typeof secret === "string") {
		if (secret.length === 0) {
			throw new Error("federation client secret is empty");
		}
		return secret;
	}
	if (typeof secret !== "function") {
		throw new Error(
			`federation client secret must be a string or a function returning one, got ${secret === null ? "null" : typeof secret}`,
		);
	}
	const resolved = await secret();
	if (typeof resolved !== "string" || resolved.length === 0) {
		throw new Error(
			"federation client secret resolver returned no usable secret (expected a non-empty string)",
		);
	}
	return resolved;
};
