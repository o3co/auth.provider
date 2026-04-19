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
import { AdapterFactoryError } from "#/adapters/AdapterFactory.mjs";
import { createKeyStoreFactory, registerBuiltinKeyStores } from "#/keys/factory.mjs";

describe("createKeyStoreFactory", () => {
	it("returns a factory with no registered types by default", () => {
		const factory = createKeyStoreFactory();

		expect(factory.registeredTypes()).toEqual([]);
	});

	it("rejects with AdapterFactoryError for an unknown type", async () => {
		const factory = createKeyStoreFactory();

		await expect(factory.create({ type: "local" })).rejects.toSatisfy((err: unknown) => {
			if (!(err instanceof AdapterFactoryError)) return false;
			return (
				err.name === "AdapterFactoryError" && err.reason === "unknown" && err.kind === "KeyStore"
			);
		});
	});
});

describe("registerBuiltinKeyStores - local HS256", () => {
	it("registers 'local' type", () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		expect(factory.registeredTypes()).toContain("local");
	});

	it("builds HS256 KeyStore with secret", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		const keyStore = await factory.create({
			type: "local",
			algorithm: "HS256",
			kid: "v1",
			secret: "s3cret",
			previousKeys: [],
		});
		expect(keyStore.algorithm).toBe("HS256");
		expect(keyStore.current.kid).toBe("v1");
	});

	it("throws clear error when HS256 secret is missing", async () => {
		const factory = createKeyStoreFactory();
		registerBuiltinKeyStores(factory);
		await expect(
			factory.create({ type: "local", algorithm: "HS256", kid: "v1", previousKeys: [] }),
		).rejects.toThrow(/secret is required for HS256/i);
	});
});
