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
 * Issue #301 — possession proof, which is the part the issue is emphatic about:
 * "A bare DeviceID is **not** authentication."
 *
 * Almost every case here is a refusal, because that is where this component's
 * value is. Accepting a valid assertion is one line of jose; the reason this
 * ships rather than leaving each deployment to hand-roll it is that the
 * refusals are easy to leave out, and leaving one out turns a login into a
 * string comparison.
 */

import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createJwtAssertionVerifier } from "#/assertions/jwtAssertionVerifier.mjs";

const ISSUER = "https://devices.example";
const AUDIENCE = "https://auth.example";

const authority = generateKeyPairSync("ed25519");
const otherAuthority = generateKeyPairSync("ed25519");

const mint = async (
	claims: Record<string, unknown> = {},
	opts: { iss?: string; aud?: string; key?: typeof authority.privateKey; expSec?: number } = {},
): Promise<string> => {
	const builder = new SignJWT({ ...claims })
		.setProtectedHeader({ alg: "EdDSA" })
		.setIssuer(opts.iss ?? ISSUER)
		.setAudience(opts.aud ?? AUDIENCE)
		.setIssuedAt();
	return builder
		.setExpirationTime(opts.expSec ?? Math.floor(Date.now() / 1000) + 300)
		.sign(opts.key ?? authority.privateKey);
};

const verifier = (overrides: Record<string, unknown> = {}) =>
	createJwtAssertionVerifier({
		key: authority.publicKey,
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["EdDSA"],
		...overrides,
	} as never);

describe("createJwtAssertionVerifier — what it accepts (#301)", () => {
	it("returns the sub as the handle for a well-formed assertion", async () => {
		const result = await verifier().verify(await mint({ sub: "device:abc" }));
		expect(result?.subjectHandle).toBe("device:abc");
	});

	it("carries a scope claim through as a ceiling", async () => {
		const result = await verifier().verify(await mint({ sub: "device:abc", scope: "read write" }));
		expect(result?.scope).toEqual(["read", "write"]);
	});

	it("omits scope entirely when the assertion names none", async () => {
		// Absent must not read as "no scopes" — that would be a ceiling of
		// nothing, refusing every request rather than constraining none.
		const result = await verifier().verify(await mint({ sub: "device:abc" }));
		expect(result?.scope).toBeUndefined();
	});

	it("takes a custom handle reader for tokens that name the device elsewhere", async () => {
		const result = await verifier({
			readSubjectHandle: (c: Record<string, unknown>) =>
				typeof c.device_id === "string" ? `device:${c.device_id}` : null,
		}).verify(await mint({ device_id: "abc" }));
		expect(result?.subjectHandle).toBe("device:abc");
	});
});

describe("createJwtAssertionVerifier — what it refuses (#301)", () => {
	it("refuses an assertion signed by another authority", async () => {
		const result = await verifier().verify(
			await mint({ sub: "device:abc" }, { key: otherAuthority.privateKey }),
		);
		expect(result).toBeNull();
	});

	it("refuses an assertion from an unexpected issuer", async () => {
		const result = await verifier().verify(
			await mint({ sub: "device:abc" }, { iss: "https://attacker.example" }),
		);
		expect(result).toBeNull();
	});

	it("refuses an assertion addressed to another service", async () => {
		// RFC 7523 §3 requires the audience check, and this is why: without it,
		// an assertion the device legitimately minted for some other API is
		// replayable here as a login.
		const result = await verifier().verify(
			await mint({ sub: "device:abc" }, { aud: "https://someone-else.example" }),
		);
		expect(result).toBeNull();
	});

	it("refuses an expired assertion", async () => {
		const result = await verifier().verify(
			await mint({ sub: "device:abc" }, { expSec: Math.floor(Date.now() / 1000) - 3600 }),
		);
		expect(result).toBeNull();
	});

	it("refuses an assertion whose algorithm is not on the list", async () => {
		const hs = await new SignJWT({ sub: "device:abc" })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.setExpirationTime("5m")
			.sign(new TextEncoder().encode("a-shared-secret-at-least-32-bytes!!"));
		expect(await verifier().verify(hs)).toBeNull();
	});

	it("refuses a verified assertion that names nobody", async () => {
		// A good signature over a token with no subject is not an
		// authentication — there is no one to log in.
		expect(await verifier().verify(await mint({}))).toBeNull();
	});

	it("refuses an empty handle as firmly as a missing one", async () => {
		expect(await verifier().verify(await mint({ sub: "" }))).toBeNull();
	});

	// The failure the issue names by name.
	it("refuses a bare identifier that is not a token at all", async () => {
		expect(await verifier().verify("device-1234")).toBeNull();
		expect(await verifier().verify("")).toBeNull();
	});

	it("tells the caller nothing about which check failed", async () => {
		// Every refusal is the same `null`. Distinguishing them would let a
		// caller probe for a valid issuer or a live device id.
		for (const bad of [
			await mint({ sub: "d" }, { key: otherAuthority.privateKey }),
			await mint({ sub: "d" }, { iss: "https://attacker.example" }),
			await mint({ sub: "d" }, { aud: "https://elsewhere.example" }),
			"not-a-jwt",
		]) {
			expect(await verifier().verify(bad)).toBeNull();
		}
	});
});

describe("createJwtAssertionVerifier — construction (#301)", () => {
	it("refuses to build without a pinned issuer or audience", async () => {
		// Both are what make the assertion this deployment's to accept. A
		// verifier missing either is a replay window, so it fails at boot.
		expect(() => verifier({ issuer: "" })).toThrow(/issuer and audience are required/);
		expect(() => verifier({ audience: "" })).toThrow(/issuer and audience are required/);
	});

	it("refuses to build without an algorithm list", () => {
		// Omitting it lets jose accept anything the key can verify, which is
		// wider than configuring one key means — and the docstring promised
		// otherwise before this was required.
		expect(() => verifier({ algorithms: [] })).toThrow(/at least one algorithm/);
	});

	it("reports its kind", () => {
		expect(verifier().kind).toBe("jwt");
	});
});
