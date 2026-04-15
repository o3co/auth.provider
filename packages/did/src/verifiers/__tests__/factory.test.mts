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
import { Ed25519PrehashVerifier } from "../ed25519Prehash.mjs";
import { Ed25519RawVerifier } from "../ed25519Raw.mjs";
import { createVerifier } from "../factory.mjs";
import { JwsVerifier } from "../jws.mjs";

describe("createVerifier", () => {
	it("returns Ed25519RawVerifier for ed25519_raw", async () => {
		const verifier = await createVerifier("ed25519_raw");
		expect(verifier).toBeInstanceOf(Ed25519RawVerifier);
	});

	it("returns JwsVerifier for ed25519_jws", async () => {
		const verifier = await createVerifier("ed25519_jws");
		expect(verifier).toBeInstanceOf(JwsVerifier);
	});

	it("returns JwsVerifier for es256_jws", async () => {
		const verifier = await createVerifier("es256_jws");
		expect(verifier).toBeInstanceOf(JwsVerifier);
	});

	it("returns JwsVerifier for es256k_jws", async () => {
		const verifier = await createVerifier("es256k_jws");
		expect(verifier).toBeInstanceOf(JwsVerifier);
	});

	it("passes pathResolver to Ed25519RawVerifier when provided", async () => {
		const pathResolver = (s: string) => s;
		const verifier = await createVerifier("ed25519_raw", pathResolver);
		expect(verifier).toBeDefined();
	});

	it("returns Ed25519PrehashVerifier for ed25519_prehash", async () => {
		const verifier = await createVerifier("ed25519_prehash");
		expect(verifier).toBeInstanceOf(Ed25519PrehashVerifier);
	});
});
