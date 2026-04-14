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
import { describe, expect, it } from "vitest";
import { extractVerificationKey } from "../../resolver/extractKey.mjs";
import type { DidDocument, JsonWebKey } from "../../resolver/types.mjs";

const did = "did:key:z6MkTest";

describe("extractVerificationKey", () => {
	it("extracts publicKeyJwk from matching verificationMethod (controller match)", async () => {
		const jwk: JsonWebKey = {
			kty: "OKP",
			crv: "Ed25519",
			x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		};
		const doc: DidDocument = {
			id: did,
			verificationMethod: [
				{
					id: `${did}#key-1`,
					type: "Ed25519VerificationKey2020",
					controller: did,
					publicKeyJwk: jwk,
				},
			],
		};

		const result = await extractVerificationKey(doc, did);

		expect(result.format).toBe("jwk");
		if (result.format === "jwk") {
			expect(result.key).toEqual(jwk);
		}
	});

	it("extracts publicKeyJwk from matching verificationMethod (id prefix match)", async () => {
		const jwk: JsonWebKey = { kty: "EC", crv: "P-256", x: "abc", y: "def" };
		const doc: DidDocument = {
			id: did,
			verificationMethod: [
				{
					id: `${did}#key-1`,
					type: "JsonWebKey2020",
					controller: "did:key:z6MkOther", // different controller
					publicKeyJwk: jwk,
				},
			],
		};

		const result = await extractVerificationKey(doc, did);

		expect(result.format).toBe("jwk");
		if (result.format === "jwk") {
			expect(result.key).toEqual(jwk);
		}
	});

	it("extracts publicKeyMultibase from matching verificationMethod", async () => {
		const multibaseKey = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
		const doc: DidDocument = {
			id: did,
			verificationMethod: [
				{
					id: `${did}#key-1`,
					type: "Ed25519VerificationKey2020",
					controller: did,
					publicKeyMultibase: multibaseKey,
				},
			],
		};

		const result = await extractVerificationKey(doc, did);

		expect(result.format).toBe("multibase");
		if (result.format === "multibase") {
			expect(result.key).toBe(multibaseKey);
		}
	});

	it("throws when verificationMethod array is absent", async () => {
		const doc: DidDocument = {
			id: did,
			// no verificationMethod
		};

		await expect(extractVerificationKey(doc, did)).rejects.toThrow();
	});

	it("throws when no verificationMethod matches the DID", async () => {
		const doc: DidDocument = {
			id: did,
			verificationMethod: [
				{
					id: "did:key:z6MkOther#key-1",
					type: "Ed25519VerificationKey2020",
					controller: "did:key:z6MkOther",
					publicKeyMultibase: "z6MkSomeKey",
				},
			],
		};

		await expect(extractVerificationKey(doc, did)).rejects.toThrow();
	});

	it("throws when matching method has no key material", async () => {
		const doc: DidDocument = {
			id: did,
			verificationMethod: [
				{
					id: `${did}#key-1`,
					type: "Ed25519VerificationKey2020",
					controller: did,
					// no publicKeyJwk or publicKeyMultibase
				},
			],
		};

		await expect(extractVerificationKey(doc, did)).rejects.toThrow();
	});
});
