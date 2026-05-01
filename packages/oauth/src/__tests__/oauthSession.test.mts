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

import {
	type ClientRepository,
	createSymmetricKeyStore,
	defineModule,
	type GrantHandler,
} from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { oauthSessionModule } from "#/oauthSession.mjs";

// ---------------------------------------------------------------------------
// Shared test-only stubs
// ---------------------------------------------------------------------------

const fakeClientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

/** Inline module that satisfies `requires: ["clientRepository"]`. */
const clientRepositoryModule = defineModule({
	name: "test:client-repository",
	provides: {
		clientRepository: () => fakeClientRepository,
	},
});

/** Inline module that satisfies `requires: ["keyStore"]`. */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-session-grant"),
	},
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("oauthSessionModule", () => {
	it("has name 'oauth-session'", () => {
		const config = makeValidAppConfig();
		const module = oauthSessionModule({ config });
		expect(module.name).toBe("oauth-session");
	});

	it("registers the session grant when config.oauth.grants.session.enabled is not false", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, grants: { ...base.oauth.grants, session: { enabled: true } } },
		};
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), clientRepositoryModule, keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(true);
		await handle.dispose();
	});

	it("contributes no grant when config.oauth.grants.session.enabled === false", async () => {
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, grants: { ...base.oauth.grants, session: { enabled: false } } },
		};
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), clientRepositoryModule, keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		expect(handle.inspect.grants.has("session")).toBe(false);
		await handle.dispose();
	});

	it("registered handler returns 401 for unauthenticated session", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [oauthSessionModule({ config }), clientRepositoryModule, keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		// TestInspect.grants is ReadonlyMap<string, unknown> because contributes-map.mts
		// uses a structural placeholder for GrantHandler until Phase 9 substitutes the
		// concrete type. Cast to the concrete GrantHandler from grants/types.mts here.
		const handler = handle.inspect.grants.get("session") as GrantHandler | undefined;
		if (!handler) throw new Error("expected session grant to be registered");
		const { result } = await handler.handle({
			body: {},
			session: { isAuthenticated: false },
			issuer: "localhost",
			metadata: {},
		});
		expect(result.status).toBe(401);
		await handle.dispose();
	});
});
