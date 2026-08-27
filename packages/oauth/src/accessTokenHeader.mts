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
 * The auth schemes that carry an access token as the credential.
 *
 * `Bearer` is RFC 6750 §2.1. `DPoP` is RFC 9449 §7.1, which requires a
 * DPoP-bound access token to be presented under its own scheme rather than
 * as a Bearer token — that separation is what lets a resource refuse a bound
 * token that arrives without its proof (issue #264).
 *
 * Which of the two a given token is *allowed* to use is decided by
 * `protectedResourceBindingMw` against the token's `cnf` claim, not here:
 * this helper only answers "is there an access token in this header, and
 * what is it?" so every protected resource extracts it the same way.
 */
const ACCESS_TOKEN_SCHEMES: ReadonlySet<string> = new Set(["bearer", "dpop"]);

/**
 * Extract the access token from an `Authorization` header value, or `null`
 * when the header carries no access token — absent, malformed, a different
 * scheme (`Basic` client authentication is the case that occurs), or a
 * scheme with an empty credential.
 *
 * The scheme is matched as a whole token, not as a prefix: `BearerToken xyz`
 * is a different scheme and returns `null`, where `startsWith("Bearer ")`
 * would have been fooled by `Bearer` + any suffix only if it also matched the
 * space — but the surrounding endpoints previously used both `startsWith`
 * and case-insensitive regexes, so pinning one behaviour in one place removes
 * the drift.
 */
export const parseAccessTokenHeader = (authorization: string | undefined): string | null => {
	if (authorization === undefined) return null;
	const separator = authorization.indexOf(" ");
	if (separator === -1) return null;
	// RFC 9110 §11.1: the scheme is case-insensitive.
	const scheme = authorization.slice(0, separator).toLowerCase();
	if (!ACCESS_TOKEN_SCHEMES.has(scheme)) return null;
	// RFC 9110 §5.6.3 allows optional whitespace around a field value.
	const token = authorization.slice(separator + 1).trim();
	return token === "" ? null : token;
};
