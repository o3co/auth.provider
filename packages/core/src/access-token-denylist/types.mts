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
 * Tracks revoked access-token jtis. Optional ComponentMap slot; when present,
 * verifyJwt consults `has(jti)` and the `/oauth/revoke` access-token path calls
 * `add(jti, expiresAtMs)`.
 *
 * `add` keeps the jti denied at least until `expiresAtMs` (the revoke route
 * passes the token's `exp` plus `REVOCATION_RETENTION_ALLOWANCE_MS`). A
 * fractional value is valid (a JWT NumericDate may be non-integer); a value that
 * is not a finite instant within the Date range (`isStorableExpiry`) is a
 * RangeError and records nothing. A past `expiresAtMs` is not an error: revoking
 * an expired token is legal (RFC 7009 §2.1).
 */
export interface AccessTokenDenylist {
	readonly kind: string;
	add(jti: string, expiresAtMs: number): Promise<void>;
	has(jti: string): Promise<boolean>;
}

/**
 * The declared-absence policy the bundled modules that read
 * `accessTokenDenylist` attach to it.
 *
 * RFC 7009 §2.2 makes `POST /oauth/revoke` answer 200 for a well-formed
 * request, so with no denylist wired the operator sees success while the JWT
 * keeps verifying until expiry. Boot therefore refuses the missing slot unless
 * `oauth.revocation.accessToken` is explicitly `"unsupported"` (omitting the
 * key is not a declaration); the endpoint then answers
 * `unsupported_token_type` instead of a hollow 200.
 *
 * One shared constant, like `AUDIT_SINK_ABSENCE_POLICY`: the boot error's
 * advice must not depend on which module tripped it, and the
 * declared-absence guard refuses policies that disagree.
 */
export const ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY = {
	configKey: ["oauth", "revocation", "accessToken"],
	absentValue: "unsupported",
	hint:
		"RFC 7009 revocation of an access token would answer 200 and leave the token valid " +
		'until it expires. Wire a shared denylist (`accessTokenDenylist.adapter = "redis"` in ' +
		"the standalone template; the bundled memoryAccessTokenDenylistModule is single-replica " +
		'only), or declare `"unsupported"` to have the endpoint reject access-token revocation ' +
		"with unsupported_token_type. Refresh-token revocation runs off the family store and is " +
		"unaffected either way.",
} as const;

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly accessTokenDenylist?: AccessTokenDenylist;
	}
}
