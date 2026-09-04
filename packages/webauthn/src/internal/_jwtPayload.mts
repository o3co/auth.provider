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

// PARITY: keep in sync with packages/oauth/src/grants/_jwtPayload.mts
// Consolidation candidate for Wave 2 — the same follow-up that owns
// _resourceIndicator.mts.

/**
 * Best-effort JWT payload decode without signature verification.
 *
 * Internal to the webauthn grant — only used to read `jti` / `exp` back off a
 * refresh token this package just minted itself, so the token can be
 * registered with a `RefreshTokenFamilyRotation`. Do NOT use it on a token
 * received from a caller: an unverified decode trusts whatever the caller
 * sent.
 *
 * Duplicated from packages/oauth/src/grants/_jwtPayload.mts for the same
 * reason `_resourceIndicator.mts` is: the webauthn package does not depend on
 * @o3co/auth-provider-oauth, and that file is file-internal to oauth/grants/
 * rather than barrel-exported.
 *
 * Returns an empty object on any parse error; callers must treat missing
 * fields as normal.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> {
	const parts = token.split(".");
	if (parts.length < 2) return {};
	try {
		return JSON.parse(Buffer.from(parts[1] ?? "", "base64url").toString("utf-8")) as Record<
			string,
			unknown
		>;
	} catch {
		return {};
	}
}
