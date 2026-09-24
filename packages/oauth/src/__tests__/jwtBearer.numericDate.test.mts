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
 * An assertion whose `exp`, `iat` or `nbf` is not a date is the client's
 * malformed assertion: `400 invalid_grant`, never a server fault.
 *
 * JSON has no Infinity, but `1e400` parses to it, and jose checks only that a
 * NumericDate claim is a number: `exp: 1e400` is never "expired". An ID-JAG
 * carrying it reached the replay seen-set, whose `RangeError` for a
 * non-finite expiry made the grant answer `503` — the server's fault, for the
 * client's malformed input. A plain RFC 7523 assertion carrying it was
 * verified, with `expiresAt: Infinity`, and refused only because the grant
 * happens to check that it can compute a lifetime from it; one with `iat` or
 * `nbf` of `-1e400` was accepted. A finite `exp` past what a Date can hold
 * (`1e300`) reaches the seen-set as a lifetime the Redis adapter cannot write.
 *
 * Driven through the real jwt-bearer grant, the real registry verifier and
 * the real memory seen-set. The assertions are signed over raw claim JSON,
 * because jose refuses to produce a non-finite claim.
 */

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import {
	type AppConfig,
	type AuthenticatedClient,
	createMemoryAssertionIssuerRegistry,
	createMemoryReplaySeenSet,
	createRegistryAssertionVerifier,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantResult,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { CompactSign } from "jose";
import { describe, expect, it } from "vitest";
import { createJwtBearerGrant } from "#/grants/jwtBearer.mjs";

const AS = "https://auth.example";
const IDP = "https://idp.example";
const DEVICES = "https://devices.example";
const CLIENT_ID = "mcp-client";

const idp = generateKeyPairSync("ed25519");
const devices = generateKeyPairSync("ed25519");

const config = {
	oauth: { jwt: { issuer: AS }, accessToken: { expiresIn: 300 } },
} as unknown as AppConfig;

const client: AuthenticatedClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedScopes: [],
	allowedAudiences: ["https://api.example"],
} as AuthenticatedClient;

const grant = () =>
	createJwtBearerGrant({
		config,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		assertionVerifier: createRegistryAssertionVerifier({
			registry: createMemoryAssertionIssuerRegistry([
				{
					issuer: IDP,
					keys: { type: "key", key: idp.publicKey },
					algorithms: ["EdDSA"],
					profile: "id-jag",
					allowedAudiences: ["https://api.example"],
				},
				{ issuer: DEVICES, keys: { type: "key", key: devices.publicKey }, algorithms: ["EdDSA"] },
			]),
			audience: AS,
			issuerIdentifier: AS,
			replaySeenSet: createMemoryReplaySeenSet(),
		}),
		userRepository: {
			authenticate: async () => null,
			authenticateByToken: async () => ({ id: "u-1" }),
		} as unknown as UserRepository,
	} as never);

/**
 * Signs `claims` as written: each `rawNumbers` entry replaces its claim with
 * the literal JSON number text, so `1e400` reaches the verifier as JSON does.
 */
const sign = (
	key: KeyObject,
	header: Record<string, unknown>,
	claims: Record<string, unknown>,
	rawNumbers: Record<string, string> = {},
): Promise<string> => {
	let json = JSON.stringify(claims);
	for (const [claim, literal] of Object.entries(rawNumbers)) {
		json = json.replace(`"${claim}":"@"`, `"${claim}":${literal}`);
	}
	return new CompactSign(new TextEncoder().encode(json))
		.setProtectedHeader({ alg: "EdDSA", ...header })
		.sign(key);
};

const now = () => Math.floor(Date.now() / 1000);
let jtiCounter = 0;

/** An ID-JAG, conformant but for the claims `rawNumbers` overrides. */
const idJag = (rawNumbers: Record<string, string> = {}, jti = `jti-${++jtiCounter}`) =>
	sign(
		idp.privateKey,
		{ typ: "oauth-id-jag+jwt" },
		{
			iss: IDP,
			sub: "user-1",
			aud: AS,
			client_id: CLIENT_ID,
			jti,
			resource: "https://api.example",
			iat: "iat" in rawNumbers ? "@" : now() - 10,
			exp: "exp" in rawNumbers ? "@" : now() + 120,
			...("nbf" in rawNumbers ? { nbf: "@" } : {}),
		},
		rawNumbers,
	);

/** A plain RFC 7523 device assertion, conformant but for the claims `rawNumbers` overrides. */
const deviceAssertion = (rawNumbers: Record<string, string> = {}) =>
	sign(
		devices.privateKey,
		{},
		{
			iss: DEVICES,
			sub: "device:1",
			aud: AS,
			exp: "exp" in rawNumbers ? "@" : now() + 120,
			...("iat" in rawNumbers ? { iat: "@" } : {}),
			...("nbf" in rawNumbers ? { nbf: "@" } : {}),
		},
		rawNumbers,
	);

const present = async (
	assertion: string,
	withClient = true,
	handler = grant(),
): Promise<GrantResult> =>
	(
		await handler.handle({
			body: { assertion },
			session: {},
			issuer: AS,
			metadata: {},
			authenticatedClient: withClient ? client : null,
		} as GrantContext)
	).result;

const malformed = {
	status: 400,
	error: "invalid_grant",
	errorDescription: "assertion did not verify",
};

describe("jwt-bearer — an ID-JAG whose date claims are not dates", () => {
	it("refuses exp: 1e400 as invalid_grant before the seen-set is asked, not 503", async () => {
		expect(await present(await idJag({ exp: "1e400" }))).toMatchObject(malformed);
	});

	it("refuses exp: -1e400", async () => {
		expect(await present(await idJag({ exp: "-1e400" }))).toMatchObject(malformed);
	});

	it("refuses an exp past what a Date can hold (1e300)", async () => {
		expect(await present(await idJag({ exp: "1e300" }))).toMatchObject(malformed);
	});

	it("refuses iat: 1e400 and iat: -1e400", async () => {
		expect(await present(await idJag({ iat: "1e400" }))).toMatchObject(malformed);
		expect(await present(await idJag({ iat: "-1e400" }))).toMatchObject(malformed);
	});

	it("refuses nbf: -1e400", async () => {
		expect(await present(await idJag({ nbf: "-1e400" }))).toMatchObject(malformed);
	});

	it("accepts a non-integer exp — RFC 7519 §2 lets a NumericDate carry a fraction — and records it once", async () => {
		const exp = String(now() + 120.5);
		const assertion = await idJag({ exp }, "jti-fractional");
		const handler = grant();
		expect((await present(assertion, true, handler)).status).toBe(200);
		expect(await present(assertion, true, handler)).toMatchObject(malformed);
	});

	it("refuses an ID-JAG that runs more than an hour past now as invalid_grant — a replay record that long is refused", async () => {
		// The ceiling private_key_jwt holds a client assertion to (core's
		// MAX_ASSERTION_LIFETIME_SECONDS): an ID-JAG's jti is remembered
		// until its exp.
		expect(await present(await idJag({ exp: String(now() + 2 * 3600) }))).toMatchObject(malformed);
		expect((await present(await idJag({ exp: String(now() + 3600 - 60) }))).status).toBe(200);
	});
});

describe("jwt-bearer — an RFC 7523 assertion whose date claims are not dates", () => {
	it("refuses exp: 1e400", async () => {
		expect(await present(await deviceAssertion({ exp: "1e400" }), false)).toMatchObject(malformed);
	});

	it("refuses iat: -1e400 and nbf: -1e400", async () => {
		expect(await present(await deviceAssertion({ iat: "-1e400" }), false)).toMatchObject(malformed);
		expect(await present(await deviceAssertion({ nbf: "-1e400" }), false)).toMatchObject(malformed);
	});

	it("still accepts a conformant one, and a non-integer exp", async () => {
		expect((await present(await deviceAssertion(), false)).status).toBe(200);
		expect(
			(await present(await deviceAssertion({ exp: String(now() + 60.25) }), false)).status,
		).toBe(200);
	});
});
