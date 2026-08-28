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
 * verifyJwt consults `has(jti)` and `/oauth/revoke` AT path calls `add(jti, expiresAtMs)`.
 *
 * Wave 2 forward-compat: signature is `add(jti, expiresAtMs, options?)`. Wave 1
 * implementations omit `options` parameter and remain valid when Wave 2 adds DPoP `cnf` binding.
 */
export interface AccessTokenDenylist {
	readonly kind: string;
	add(jti: string, expiresAtMs: number): Promise<void>;
	has(jti: string): Promise<boolean>;
}

/**
 * The declared-absence policy the bundled modules that read
 * `accessTokenDenylist` attach to it (#375, folding #277's bespoke boot
 * check onto the #363 vocabulary).
 *
 * RFC 7009 §2.2 makes `POST /oauth/revoke` answer 200 for a well-formed
 * request, so the 200 is the operator's only signal that anything happened —
 * and with no denylist wired, nothing does: the endpoint verified the token,
 * logged a warning nobody reads mid-incident, and the JWT kept verifying
 * everywhere until expiry. #277 refused boot for that state with a bespoke
 * stage ("13.9"); this policy is the same refusal through the generic
 * declared-absence guard. Omission of `oauth.revocation.accessToken` means
 * NOT declared — every config written before #277 omits the key, and those
 * are exactly the deployments whose revocation endpoint answered 200 with
 * nothing behind it — so only an explicit `"unsupported"` excuses the
 * missing slot, and the endpoint then answers `unsupported_token_type`
 * instead of a hollow 200.
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
