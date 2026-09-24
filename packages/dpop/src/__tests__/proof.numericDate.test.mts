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
 * A DPoP proof whose `iat` — or an `exp` / `nbf` it carries — is not a date
 * is a malformed proof: `invalid_dpop_proof`, reason `malformed_proof`.
 *
 * JSON's `1e400` parses to Infinity, and jose checks only that the claim is
 * a number. The iat window happened to refuse an infinite `iat`, as
 * `iat_out_of_window` with a `drift` of Infinity — an audit record that
 * describes a finite clock difference — and a proof carrying `exp: 1e400`
 * was accepted. Driven through the real mechanism and the real memory
 * seen-set; the proofs are signed over raw claim JSON, because jose refuses
 * to produce a non-finite claim.
 */

import { createMemoryReplaySeenSet } from "@o3co/auth-provider-core";
import type { Request } from "express";
import { CompactSign, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { createDPoPMechanism } from "#/verifier.mjs";

const ISSUER = "https://as.example";

const mechanism = () =>
	createDPoPMechanism({
		issuer: ISSUER,
		replaySeenSet: createMemoryReplaySeenSet(),
		iatWindowSeconds: 60,
		algWhitelist: ["ES256"],
	});

/** A proof for `POST /token`, conformant but for `dates`, written as raw JSON number text. */
const proof = async (dates: Record<string, string>): Promise<string> => {
	const { publicKey, privateKey } = await generateKeyPair("ES256");
	const jwk = await exportJWK(publicKey);
	const numbers = Object.entries({ iat: String(Math.floor(Date.now() / 1000)), ...dates })
		.map(([claim, literal]) => `"${claim}":${literal}`)
		.join(",");
	const json = `{"htm":"POST","htu":"${ISSUER}/token","jti":"${crypto.randomUUID()}",${numbers}}`;
	return new CompactSign(new TextEncoder().encode(json))
		.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
		.sign(privateKey);
};

const request = (dpop: string): Request =>
	({
		get: ((name: string) => (name.toLowerCase() === "dpop" ? dpop : undefined)) as Request["get"],
		method: "POST",
		originalUrl: "/token",
		protocol: "https",
	}) as Request;

describe("DPoP — date claims that are not dates", () => {
	for (const [claim, literal] of [
		["iat", "1e400"],
		["iat", "-1e400"],
		["iat", "1e300"],
		["exp", "1e400"],
		["nbf", "-1e400"],
	] as const) {
		it(`refuses ${claim}: ${literal} as a malformed proof`, async () => {
			await expect(
				mechanism().extract(request(await proof({ [claim]: literal }))),
			).rejects.toMatchObject({
				name: "DPoPError",
				code: "invalid_dpop_proof",
				reason: "malformed_proof",
			});
		});
	}

	it("accepts a non-integer iat inside the window — RFC 7519 §2 lets a NumericDate carry a fraction", async () => {
		const iat = String(Math.floor(Date.now() / 1000) - 0.5);
		await expect(mechanism().extract(request(await proof({ iat })))).resolves.toMatchObject({
			kind: "dpop",
		});
	});
});
