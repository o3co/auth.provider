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
import { createSymmetricKeyStore } from "../KeyStore.mjs";

describe("SymmetricKeyStore", () => {
	const keyStore = createSymmetricKeyStore("test-secret");

	it("has algorithm HS256", () => {
		expect(keyStore.algorithm).toBe("HS256");
	});

	it("has default kid v0", () => {
		expect(keyStore.current.kid).toBe("v0");
	});

	it("accepts custom kid", () => {
		const ks = createSymmetricKeyStore("test-secret", "custom-kid");
		expect(ks.current.kid).toBe("custom-kid");
	});

	it("getSigningKey returns kid and privateKey", () => {
		const signingKey = keyStore.getSigningKey();
		expect(signingKey.kid).toBe("v0");
		expect(signingKey.privateKey).toBeDefined();
	});

	it("getVerificationKey returns key for current kid", () => {
		const key = keyStore.getVerificationKey("v0");
		expect(key).toBeDefined();
	});

	it("getVerificationKey throws for unknown kid", () => {
		expect(() => keyStore.getVerificationKey("unknown")).toThrow();
	});

	it("getVerificationKeys returns current key only (no previous keys)", () => {
		const keys = keyStore.getVerificationKeys();
		expect(keys).toHaveLength(1);
		expect(keys[0].kid).toBe("v0");
	});

	it("current.privateKey and current.publicKey are the same for symmetric", () => {
		expect(keyStore.current.privateKey).toBe(keyStore.current.publicKey);
	});
});
