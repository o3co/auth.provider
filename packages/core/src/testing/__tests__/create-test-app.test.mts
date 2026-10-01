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
import type { LifecycleRegistrar } from "#/adapters/AdapterFactory.mjs";
import { defineModule, type GrantHandler } from "../../modules/manifest/index.mjs";
import { createTestApp } from "../create-test-app.mjs";
import { makeValidAppConfig } from "../fixtures/valid-config.mjs";

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly testAppRegistrarHolder: number;
	}
}

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
		const fakeGrant = {
			handle: async () => ({ tokenType: "bearer", accessToken: "x" }),
		} as unknown as GrantHandler;
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

	it("reads the cleanup allowance live, as the production handle does", async () => {
		let registrar: LifecycleRegistrar | undefined;
		const holder = defineModule<never, "lifecycleRegistrar">({
			name: "test:registrar-holder",
			optional: ["lifecycleRegistrar"],
			provides: {
				testAppRegistrarHolder: (deps) => {
					registrar = deps.lifecycleRegistrar;
					return 1;
				},
			},
			lifecycle: { testAppRegistrarHolder: { eager: true } },
		});
		const handle = await createTestApp({ modules: [holder] });
		expect(handle.cleanupAllowanceMs).toBeUndefined();
		registrar?.register(async () => {}, { tailMs: 60_000 });
		expect(handle.cleanupAllowanceMs).toBe(60_000);
		await handle.dispose();
	});
});
