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
 * `effectiveExpiresAt` ends there, and a token written back states that end:
 * nothing it lost is invented. A stored value that is not what its type says
 * reads as no instant, never as a throw.
 */

import { type HeldUpstreamToken, instantOf } from "../federations/token-lifetime.mjs";
import type { FederationGrantCredentials, FederationGrantCredentialsInput } from "./types.mjs";

/** A grant credential's access token, as a store answers it. */
export type StoredAccessToken = NonNullable<FederationGrantCredentials["accessToken"]>;

/** A grant credential's access token, as a writer hands it to a store. */
export type WrittenAccessToken = NonNullable<FederationGrantCredentialsInput["accessToken"]>;

/** The access token to store, from a finite reading that names its issued lifetime. */
export function federationGrantAccessToken(
	token: Pick<StoredAccessToken, "value" | "tokenType" | "scopes">,
	lifetime: {
		readonly obtainedAt: Date;
		readonly expiresAt: Date;
		readonly issuedLifetime: number;
	},
): WrittenAccessToken {
	return {
		value: token.value,
		tokenType: token.tokenType,
		obtainedAt: lifetime.obtainedAt,
		issuedLifetime: lifetime.issuedLifetime,
		effectiveExpiresAt: lifetime.expiresAt,
		scopes: [...token.scopes],
	};
}

/**
 * The stored access token as a token held. A start, an end or a lifetime
 * that is no instant or no finite number reads as an Invalid Date, which
 * `judgeHeldUpstreamToken` does not believe: the token is refreshed.
 */
export function federationGrantHeldToken(token: StoredAccessToken): HeldUpstreamToken {
	const obtainedAt = instantOf(token.obtainedAt) ?? Number.NaN;
	const lifetime = token.issuedLifetime;
	const issuedEnd = Number.isFinite(lifetime) ? obtainedAt + lifetime * 1000 : Number.NaN;
	const effective = token.effectiveExpiresAt;
	const end =
		effective === undefined ? issuedEnd : Math.min(instantOf(effective) ?? Number.NaN, issuedEnd);
	return { obtainedAt: new Date(obtainedAt), expiresAt: new Date(end) };
}

/**
 * A stored access token written back as it is: it states the end it is read
 * to have. Its fields are read by name, never spread, so a token a store
 * answers as a class instance whose fields are getters keeps them; its dates
 * are copies, so nothing the store holds is shared.
 */
export function federationGrantKeptAccessToken(token: StoredAccessToken): WrittenAccessToken {
	const held = federationGrantHeldToken(token);
	return federationGrantAccessToken(token, {
		obtainedAt: held.obtainedAt,
		expiresAt: held.expiresAt,
		issuedLifetime: token.issuedLifetime,
	});
}
