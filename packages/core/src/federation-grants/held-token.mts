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
 * The stored access token of a grant's credential, written from a lifetime
 * reading and read back as a token held. Keeps the three facts the reading
 * answers — when it was obtained, the lifetime issued, when it ends — and
 * never ends a token after `obtainedAt` + `issuedLifetime`. A record without
 * `effectiveExpiresAt` ends there: nothing it lost is invented.
 */

import type { HeldUpstreamToken } from "../federations/token-lifetime.mjs";
import type { FederationGrantCredentials } from "./types.mjs";

type StoredAccessToken = NonNullable<FederationGrantCredentials["accessToken"]>;

/** The access token to store, from a finite reading that names its issued lifetime. */
export function federationGrantAccessToken(
	token: Pick<StoredAccessToken, "value" | "tokenType" | "scopes">,
	lifetime: {
		readonly obtainedAt: Date;
		readonly expiresAt: Date;
		readonly issuedLifetime: number;
	},
): StoredAccessToken {
	return {
		value: token.value,
		tokenType: token.tokenType,
		obtainedAt: lifetime.obtainedAt,
		issuedLifetime: lifetime.issuedLifetime,
		effectiveExpiresAt: lifetime.expiresAt,
		scopes: [...token.scopes],
	};
}

/** The stored access token as a token held. An end that is not an instant reads as an Invalid Date. */
export function federationGrantHeldToken(token: StoredAccessToken): HeldUpstreamToken {
	const issuedEnd = token.obtainedAt.getTime() + token.issuedLifetime * 1000;
	const effective = token.effectiveExpiresAt;
	return {
		obtainedAt: token.obtainedAt,
		expiresAt: new Date(
			effective === undefined ? issuedEnd : Math.min(effective.getTime(), issuedEnd),
		),
	};
}
