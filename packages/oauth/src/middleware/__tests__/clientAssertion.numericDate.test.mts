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
 * A `private_key_jwt` client assertion whose `exp`, `iat` or `nbf` is not a
 * date is refused as the client's malformed assertion — `401 invalid_client`,
 * logged as `numeric_date` — before any expiry is computed from it.
 *
 * jose checks only that a NumericDate claim is a number, and JSON's `1e400`
 * parses to Infinity. The lifetime and age checks happened to refuse an
 * infinite `exp` or `iat`, under reasons that describe a finite one; an
 * `nbf` of `-1e400` was accepted. Driven through the real verifier with the
 * real memory seen-set; assertions are signed over raw claim JSON, because
 * jose refuses to produce a non-finite claim.
 */

import { randomUUID } from "node:crypto";
import {
	createMemoryReplaySeenSet,
	type Logger,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { CompactSign, exportJWK, generateKeyPair, type JWK } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
	createClientAssertionVerifier,
	JWT_BEARER_CLIENT_ASSERTION_TYPE,
} from "#/middleware/clientAssertion.mjs";

const ISSUER = "https://auth.test";
const TOKEN_ENDPOINT = "https://auth.test/oauth/token";
const CLIENT_ID = "rp-1";

let privateKey: CryptoKey;
let publicJwk: JWK;

beforeAll(async () => {
	const pair = await generateKeyPair("ES256");
	privateKey = pair.privateKey;
	publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1" };
});

const client = (): PublicClient => ({
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "private_key_jwt",
	allowedRedirectUris: [],
	allowedScopes: [],
	jwks: { keys: [publicJwk] },
});

const spyLogger = () => {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: () => logger,
	};
	return logger;
};

const now = () => Math.floor(Date.now() / 1000);

/** A conformant assertion but for `dates`, written as raw JSON number text. */
const assertion = (dates: Partial<Record<"exp" | "iat" | "nbf", string>>): Promise<string> => {
	const fields = {
		exp: String(now() + 60),
		iat: String(now()),
		...dates,
	};
	const numbers = Object.entries(fields)
		.map(([claim, literal]) => `"${claim}":${literal}`)
		.join(",");
	const json = `{"iss":"${CLIENT_ID}","sub":"${CLIENT_ID}","aud":"${TOKEN_ENDPOINT}","jti":"${randomUUID()}",${numbers}}`;
	return new CompactSign(new TextEncoder().encode(json))
		.setProtectedHeader({ alg: "ES256", kid: "k1" })
		.sign(privateKey);
};

const verify = async (dates: Partial<Record<"exp" | "iat" | "nbf", string>>) => {
	const logger = spyLogger();
	const outcome = await createClientAssertionVerifier({
		issuer: ISSUER,
		tokenEndpoint: TOKEN_ENDPOINT,
		replaySeenSet: createMemoryReplaySeenSet(),
		logger: logger as unknown as Logger,
	}).verify(
		{
			client_assertion_type: JWT_BEARER_CLIENT_ASSERTION_TYPE,
			client_assertion: await assertion(dates),
		},
		async (id) => (id === CLIENT_ID ? client() : null),
	);
	return { outcome, logger };
};

describe("private_key_jwt — date claims that are not dates", () => {
	for (const [claim, literal] of [
		["exp", "1e400"],
		["exp", "1e300"],
		["iat", "1e400"],
		["iat", "-1e400"],
		["nbf", "-1e400"],
	] as const) {
		it(`refuses ${claim}: ${literal} as invalid_client, logged as numeric_date`, async () => {
			const { outcome, logger } = await verify({ [claim]: literal });
			expect(outcome).toMatchObject({ kind: "refused", status: 401, error: "invalid_client" });
			expect(logger.warn).toHaveBeenCalledWith(
				expect.objectContaining({ reason: "numeric_date", clientId: CLIENT_ID }),
				"client_assertion_refused",
			);
		});
	}

	it("accepts a non-integer exp and iat — RFC 7519 §2 lets a NumericDate carry a fraction", async () => {
		const { outcome } = await verify({
			exp: String(now() + 60.5),
			iat: String(now() - 0.25),
		});
		expect(outcome).toMatchObject({ kind: "ok" });
	});
});
