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
 * An assertion's `iss` is the client's input, read before any signature is
 * checked, and it is handed to `AssertionIssuerRegistry.findIssuer` — a
 * registry a deployment may back with its own store, one that throws on
 * input it cannot handle. A registry that throws is an outage (`503`), so an
 * `iss` that cannot name an issuer — longer than 256 characters, or carrying
 * a control character: core's identifier rule, the one `client_id` is held
 * to — is refused without a lookup, the way an unknown issuer is. And an
 * issuer registered under such a name could never be reached, so
 * `checkAssertionIssuerEntry` refuses it.
 */

import { generateKeyPairSync } from "node:crypto";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import {
	type AssertionIssuerEntry,
	type AssertionIssuerRegistry,
	checkAssertionIssuerEntry,
} from "#/assertions/issuerRegistry.mjs";
import { createRegistryAssertionVerifier } from "#/assertions/registryAssertionVerifier.mjs";
import { consoleLogger } from "#/logging/consoleLogger.mjs";
import { MAX_IDENTIFIER_LENGTH } from "#/security/identifier.mjs";

const AS = "https://auth.example";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");

/** A store-backed registry whose driver refuses a control character. */
const recordingRegistry = () => {
	const asked: string[] = [];
	const registry: AssertionIssuerRegistry = {
		kind: "store",
		findIssuer: async (issuer) => {
			asked.push(issuer);
			// biome-ignore lint/suspicious/noControlCharactersInRegex: the driver's refusal is what is modelled.
			if (/[\u0000-\u001f]/.test(issuer)) throw new Error("driver refused the parameter");
			return null;
		},
	};
	return { registry, asked };
};

const assertionFrom = (iss: string) => {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({})
		.setProtectedHeader({ alg: "EdDSA" })
		.setIssuer(iss)
		.setSubject("device:1")
		.setAudience(AS)
		.setExpirationTime(now + 60)
		.sign(privateKey);
};

const MALFORMED: ReadonlyArray<readonly [string, string]> = [
	["a NUL byte", "https://idp.example\u0000"],
	["a line feed", "https://idp.example\nx"],
	["a C1 control character", "https://idp.example\u0085"],
	["more than 256 characters", `https://idp.example/${"p".repeat(MAX_IDENTIFIER_LENGTH)}`],
];

describe("createRegistryAssertionVerifier — an iss that cannot name an issuer", () => {
	for (const [label, iss] of MALFORMED) {
		it(`refuses one carrying ${label} without asking the registry, and says why`, async () => {
			const { registry, asked } = recordingRegistry();
			const warn = vi.fn();
			const verifier = createRegistryAssertionVerifier({
				registry,
				audience: AS,
				logger: { ...consoleLogger, warn },
			});
			expect(await verifier.verify(await assertionFrom(iss))).toBeNull();
			expect(asked).toEqual([]);
			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ reason: "malformed_issuer" }),
				"jwt_bearer_assertion_refused",
			);
			// The refused iss is the client's text: never logged.
			expect(JSON.stringify(warn.mock.calls)).not.toContain("idp.example");
		});
	}

	it("still asks the registry for an iss at the bound", async () => {
		const { registry, asked } = recordingRegistry();
		const iss = "i".repeat(MAX_IDENTIFIER_LENGTH);
		const verifier = createRegistryAssertionVerifier({ registry, audience: AS });
		expect(await verifier.verify(await assertionFrom(iss))).toBeNull();
		expect(asked).toEqual([iss]);
	});
});

describe("checkAssertionIssuerEntry — an issuer no assertion could name", () => {
	const entry = (issuer: string): AssertionIssuerEntry => ({
		issuer,
		keys: { type: "key", key: publicKey },
		algorithms: ["EdDSA"],
		allowedSubjects: undefined,
		allowedScopes: undefined,
		allowedAudiences: undefined,
		allowedClients: undefined,
		expiresAt: undefined,
		profile: undefined,
		clockToleranceSeconds: undefined,
	});
	for (const [label, iss] of MALFORMED) {
		it(`refuses one carrying ${label}, without repeating it`, () => {
			expect(() => checkAssertionIssuerEntry(entry(iss))).toThrow(/issuer/);
			expect(() => checkAssertionIssuerEntry(entry(iss))).toThrow(
				expect.objectContaining({ message: expect.not.stringContaining("idp.example") }),
			);
		});
	}
});
