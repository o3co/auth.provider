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

import { createHash, timingSafeEqual } from "node:crypto";
import { decodeProtectedHeader } from "jose";

/**
 * `at_hash` (OIDC Core §3.3.2.11, #524).
 *
 * When the id_token carries `at_hash`, it binds the access token that came
 * with it: the left-most half of the access token's hash, under the hash
 * function the id_token's own `alg` names, base64url-encoded. openid-client
 * does not check it on the code flow — both tokens arrive over the same TLS
 * response, so the binding is weak there — but an IdP that sends the claim
 * means it, and a mismatch is a response that has been tampered with.
 */

function hashFor(alg: string): string {
	const sized = /^(?:RS|PS|ES|HS)(256|384|512)$/.exec(alg);
	if (sized) return `sha${sized[1]}`;
	if (alg === "ES256K") return "sha256";
	if (alg === "EdDSA" || alg === "Ed25519") return "sha512";
	throw new Error(`at_hash cannot be verified for a JWS alg of ${JSON.stringify(alg)}`);
}

/** The `at_hash` value for `accessToken` on an id_token signed with `alg`. */
export function computeAtHash(accessToken: string, alg: string): string {
	const digest = createHash(hashFor(alg)).update(accessToken).digest();
	return digest.subarray(0, digest.length / 2).toString("base64url");
}

/** Throws unless `atHash` is the claim `idToken` should carry for `accessToken`. */
export function verifyAtHash(
	label: string,
	idToken: string,
	accessToken: string,
	atHash: unknown,
): void {
	if (typeof atHash !== "string" || atHash.length === 0) {
		throw new Error(`${label}: id_token at_hash is not a string`);
	}
	let alg: unknown;
	try {
		alg = decodeProtectedHeader(idToken).alg;
	} catch {
		alg = undefined;
	}
	if (typeof alg !== "string") {
		throw new Error(`${label}: id_token has no alg header to verify at_hash with`);
	}
	let expected: string;
	try {
		expected = computeAtHash(accessToken, alg);
	} catch (err) {
		throw new Error(`${label}: ${err instanceof Error ? err.message : String(err)}`, {
			cause: err,
		});
	}
	const presented = Buffer.from(atHash);
	const wanted = Buffer.from(expected);
	if (presented.length !== wanted.length || !timingSafeEqual(presented, wanted)) {
		throw new Error(
			`${label}: id_token at_hash does not match the access token it was issued with (OIDC Core §3.3.2.11)`,
		);
	}
}
