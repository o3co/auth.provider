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
import { createMfaProviderFactory } from "#/mfa/factory.mjs";
import { createTestMfaProvider } from "./fixtures.mjs";

describe("createMfaProviderFactory", () => {
	it("creates an adapter factory and resolves registered providers", async () => {
		const factory = createMfaProviderFactory();
		factory.register("totp", () => createTestMfaProvider({ kind: "totp" }));
		const provider = await factory.create({ type: "totp" });
		expect(provider.kind).toBe("totp");
	});

	it("throws on unknown kind via AdapterFactoryError", async () => {
		const factory = createMfaProviderFactory();
		await expect(factory.create({ type: "missing" })).rejects.toThrow();
	});
});
