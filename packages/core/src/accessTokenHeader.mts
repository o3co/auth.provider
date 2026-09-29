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
 */

import { BINDING_PROFILES } from "./grants/confirmationMatch.mjs";

/** An auth scheme that carries an access token, lowercased. */
export type AccessTokenScheme =
	| "bearer"
	| (typeof BINDING_PROFILES)[keyof typeof BINDING_PROFILES]["scheme"];

/**
 * The auth schemes that carry an access token as the credential.
 *
 * `Bearer` is RFC 6750 §2.1. The rest are the per-binding presentation schemes
 * from `BINDING_PROFILES`, today only `DPoP` (RFC 9449 §7.1 requires a
 * DPoP-bound token to be presented under its own scheme, which lets a resource
 * refuse a bound token that arrives without its proof). Deriving the set from
 * the profiles keeps the parsed schemes in step with the bindings.
 *
 * Which scheme a given token may use is decided by
 * `protectedResourceBindingMw` against its `cnf` claim, not here.
 */
const ACCESS_TOKEN_SCHEMES: ReadonlySet<string> = new Set([
	"bearer",
	...Object.values(BINDING_PROFILES).map((profile) => profile.scheme),
]);

export interface AccessTokenAuthorization {
	readonly scheme: AccessTokenScheme;
	readonly token: string;
}

/**
 * Split an `Authorization` header value into the (lowercased) access-token
 * scheme and the token it carries, or `null` when the header carries no access
 * token: absent, malformed, a different scheme (e.g. `Basic` client
 * authentication), or an empty credential.
 *
 * The scheme is matched as a whole token, not a prefix: `BearerToken xyz` is a
 * different scheme and returns `null`. Every protected resource parses through
 * here so the behaviour cannot drift between endpoints.
 *
 * Callers that only need the token use {@link parseAccessTokenHeader}; this
 * variant exists for `protectedResourceBindingMw`, which must also check the
 * scheme against the binding the token's `cnf` names.
 */
export const parseAccessTokenAuthorization = (
	authorization: string | undefined,
): AccessTokenAuthorization | null => {
	if (authorization === undefined) return null;
	const separator = authorization.indexOf(" ");
	if (separator === -1) return null;
	// RFC 9110 §11.1: the scheme is case-insensitive.
	const scheme = authorization.slice(0, separator).toLowerCase();
	if (!ACCESS_TOKEN_SCHEMES.has(scheme)) return null;
	// RFC 9110 §5.6.3 allows optional whitespace around a field value.
	const token = authorization.slice(separator + 1).trim();
	return token === "" ? null : { scheme: scheme as AccessTokenScheme, token };
};

/**
 * Extract the access token from an `Authorization` header value, or `null`
 * when the header carries no access token. See
 * {@link parseAccessTokenAuthorization} for the exact parsing contract.
 */
export const parseAccessTokenHeader = (authorization: string | undefined): string | null =>
	parseAccessTokenAuthorization(authorization)?.token ?? null;
