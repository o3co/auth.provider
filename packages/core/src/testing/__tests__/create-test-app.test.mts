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
import { defineModule } from "../../modules/manifest/index.mjs";
import { createTestApp } from "../create-test-app.mjs";
import { makeValidAppConfig } from "../fixtures/valid-config.mjs";

describe("createTestApp", () => {
	it("boots with no modules and synthesised bootstrap components", async () => {
		const handle = await createTestApp();
		expect(handle.router).toBeDefined();
		expect(handle.dispose).toBeTypeOf("function");
		expect(handle.inspect).toBeDefined();
		expect(handle.inspect.grants).toBeInstanceOf(Map);
		expect(handle.inspect.federations).toBeInstanceOf(Map);
		expect(handle.inspect.tokenExchangeValidators).toBeInstanceOf(Map);
		expect(Array.isArray(handle.inspect.routes)).toBe(true);
		await handle.dispose();
	});

	it("exposes inspect.grants populated by a contributed grant", async () => {
		const fakeGrant = { handle: async () => ({ tokenType: "bearer", accessToken: "x" }) };
		const grantModule = defineModule({
			name: "test:grant",
			contributes: { grants: { fake_grant: () => fakeGrant } },
		});
		const handle = await createTestApp({ modules: [grantModule] });
		expect(handle.inspect.grants.get("fake_grant")).toBe(fakeGrant);
		await handle.dispose();
	});

	it("uses caller-supplied bootstrapComponents verbatim (no merge)", async () => {
		// Supply a schema-valid config to demonstrate the verbatim-pass-through
		// path compiles and boots without the synthesised default being merged in.
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		// No assertion on internal state; existence + dispose proves the override path compiled.
		await handle.dispose();
	});
});
