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
 * What a key id must look like — the one rule for a `kid` a keystore is
 * configured with and a `kid` header `verifyJwt` will look up.
 *
 * RFC 7515 §4.1.4 makes `kid` a case-sensitive string and bounds nothing. The
 * kids this server issues are short, operator-chosen names
 * (`oauth.jwt.signingKey`'s `kid`, `v0` by default). `verifyJwt` refuses a
 * header `kid` that is not well-formed as `kid_unknown` before any keystore
 * sees it, so a keystore of your own never receives an unbounded or
 * unprintable, attacker-chosen value to look up. And because the keystores
 * and `oauth.jwt.signingKey` refuse such a kid when they are built, a token
 * this server signed always carries a kid it will look up: a configured kid
 * the verifier refused would have made every token the server signed fail
 * as the client's fault.
 */

import {
	describeMalformedIdentifier,
	isWellFormedIdentifier,
	MAX_IDENTIFIER_LENGTH,
} from "../security/identifier.mjs";

/** The longest `kid` this server issues or looks up. */
export const MAX_KID_LENGTH = MAX_IDENTIFIER_LENGTH;

/**
 * Whether `kid` is a well-formed key id: a non-empty string of at most
 * {@link MAX_KID_LENGTH} characters with no control character.
 */
export const isWellFormedKid = (kid: unknown): kid is string => isWellFormedIdentifier(kid);

/**
 * Refuses, when a keystore is built, a configured kid `verifyJwt` would
 * refuse. `kids` names each by where it was configured (`kid`,
 * `previousKeys[0].kid`); the message names that place and what is wrong,
 * never the kid itself.
 */
export function assertWellFormedKids(
	owner: string,
	kids: ReadonlyArray<readonly [where: string, kid: unknown]>,
): void {
	for (const [where, kid] of kids) {
		if (!isWellFormedKid(kid)) {
			throw new Error(
				`${owner}: ${where} is not a usable key id (${describeMalformedIdentifier(kid)}). ` +
					`A kid must be a string of 1 to ${MAX_KID_LENGTH} characters with no control ` +
					"character: verifyJwt refuses any other kid as kid_unknown, so every token signed " +
					"under it would be refused.",
			);
		}
	}
}
