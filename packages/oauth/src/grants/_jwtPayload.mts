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
 * Best-effort JWT payload decode without signature verification.
 *
 * Internal to grants/ — only used to extract jti/exp/family_id from tokens
 * we just minted ourselves for the purpose of registering them with a
 * RefreshTokenStore. Do NOT use this on tokens received from clients
 * without a prior jwtVerify — an unsigned decode trusts the caller's
 * token format implicitly.
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
