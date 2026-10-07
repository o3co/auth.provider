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
 * Most IdPs issue a long-lived opaque string, and that stays the shape a
 * config file can carry — `federations.google.clientSecret = "..."` is
 * unchanged and keeps working.
 *
 * Some do not. Apple's `client_secret` is an ES256 JWT the relying party signs
 * itself, capped at six months, so it has to be regenerated: expressing it as
 * a value would mean a deployment that silently stops authenticating half a
 * year after it was configured. The function form lets the adapter own that
 * lifecycle — including any caching, which this module deliberately does not
 * do, because only the adapter knows when its secret expires.
 *
 * The union (rather than a second `clientSecretProvider` key) is the whole
 * API: one field, one meaning — "the secret to present at the token
 * endpoint" — with the callable form saying only that it is computed rather
 * than stored.
 */
export type FederationClientSecret = string | (() => string | Promise<string>);

/**
 * Resolve a {@link FederationClientSecret} to the string to present at the
 * token endpoint.
 *
 * Called once per token exchange (and per refresh), never memoised here. An
 * empty or non-string result is rejected rather than forwarded: posting an
 * empty `client_secret` to an IdP produces an opaque `invalid_client` from
 * upstream, which is a much harder thing to diagnose than a local throw
 * naming the federation contract.
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
