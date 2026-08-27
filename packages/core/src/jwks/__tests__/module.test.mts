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

import express from "express";
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createAsymmetricKeyStore, createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { defineModule } from "../../modules/index.mjs";
import { createTestApp } from "../../testing/create-test-app.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { jwksModule } from "../module.mjs";

// #282: the JWKS route only publishes a key set for an asymmetric keystore,
// so the module's serve-path tests run against EdDSA — the shipped default.
const eddsaPair = await generateKeyPair("EdDSA", { extractable: true });
const eddsaKeyStore = await createAsymmetricKeyStore({
	algorithm: "EdDSA",
	kid: "jwks-module-test",
	privateKeyPem: await exportPKCS8(eddsaPair.privateKey),
	publicKeyPem: await exportSPKI(eddsaPair.publicKey),
});

/** Inline module satisfying jwksModule's `requires: ["keyStore"]`. */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => eddsaKeyStore,
	},
});

/** Same slot, symmetric — used to pin the "publishes nothing" refusal. */
const hs256KeyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-jwks-module!!!!"),
	},
});

function withJwksPath(jwksPath: string) {
	const config = makeValidAppConfig() as { oauth?: { jwt?: Record<string, unknown> } };
	return {
		...config,
		oauth: {
			...config.oauth,
			jwt: { ...config.oauth?.jwt, jwksPath },
		},
	} as unknown as ReturnType<typeof makeValidAppConfig>;
}

describe("jwksModule", () => {
	it("contributes a route with id 'jwks' (mounted unconditionally, no issuer needed)", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [jwksModule, keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const routeIds = handle.inspect.routes.map((r) => r.contribution.id);
		expect(routeIds).toContain("jwks");
		await handle.dispose();
	});

	it("serves the default /.well-known/jwks.json (reachable, not 404)", async () => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [jwksModule, keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const res = await request(app).get("/.well-known/jwks.json");
		expect(res.status).toBe(200);
		expect(Array.isArray(res.body.keys)).toBe(true);
		expect(res.body.keys).toHaveLength(1);
		expect(res.body.keys[0].alg).toBe("EdDSA");
		expect(res.body.keys[0].kty).toBe("OKP");
		// Default Cache-Control so verifiers cache the key set.
		expect(res.headers["cache-control"]).toBe("public, max-age=300");
		await handle.dispose();
	});

	it("refuses to publish an empty key set when the keystore is symmetric (#282)", async () => {
		// End-to-end through the module, not just the route factory: an HS256
		// deployment that wires jwksModule used to advertise a `jwks_uri` that
		// answered 200 with zero keys.
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [jwksModule, hs256KeyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const res = await request(app).get("/.well-known/jwks.json");
		expect(res.status).toBe(404);
		expect(res.body.error).toBe("jwks_not_published");
		expect(res.body.keys).toBeUndefined();
		expect(res.headers["cache-control"]).toBe("no-store");
		await handle.dispose();
	});

	it("reflects a configured oauth.jwt.jwksCacheMaxAge in Cache-Control", async () => {
		const config = makeValidAppConfig() as { oauth?: { jwt?: Record<string, unknown> } };
		const withMaxAge = {
			...config,
			oauth: { ...config.oauth, jwt: { ...config.oauth?.jwt, jwksCacheMaxAge: 3600 } },
		} as unknown as ReturnType<typeof makeValidAppConfig>;
		const handle = await createTestApp({
			modules: [jwksModule, keyStoreModule],
			bootstrapComponents: { config: withMaxAge, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const res = await request(app).get("/.well-known/jwks.json");
		expect(res.headers["cache-control"]).toBe("public, max-age=3600");
		await handle.dispose();
	});

	it("serves the configured oauth.jwt.jwksPath override (and not the default)", async () => {
		const config = withJwksPath("/keys/jwks.json");
		const handle = await createTestApp({
			modules: [jwksModule, keyStoreModule],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		expect((await request(app).get("/keys/jwks.json")).status).toBe(200);
		expect((await request(app).get("/.well-known/jwks.json")).status).toBe(404);
		await handle.dispose();
	});
});

describe("jwksModule — discoveryMetadata contribution (OIDC aggregator)", () => {
	it("contributes the issuer-relative default jwks_uri so core advertises it in discovery", () => {
		const config = makeValidAppConfig();
		const factory = jwksModule.contributes?.discoveryMetadata?.[0];
		expect(factory).toBeDefined();
		const meta = factory?.({ config } as never);
		// jwks owns `jwks_uri`; the aggregator prefixes it with the issuer. The
		// path must match the route the same module registers (single source of
		// truth via resolveJwksPath) so discovery never advertises a dangling URI.
		expect(meta?.endpoints?.jwks_uri).toBe("/.well-known/jwks.json");
	});

	it("reflects a configured oauth.jwt.jwksPath override in the contributed jwks_uri", () => {
		const config = withJwksPath("/keys/jwks.json");
		const meta = jwksModule.contributes?.discoveryMetadata?.[0]?.({ config } as never);
		expect(meta?.endpoints?.jwks_uri).toBe("/keys/jwks.json");
	});
});

describe("jwksModule — route collision detection", () => {
	it("advertises GET <jwksPath> so a module claiming the same route fails the boot fast", async () => {
		// jwksModule mounts its router at "/" and registers the JWKS path
		// internally; without a `routes` advertisement the boot collision checker
		// cannot see the effective GET <jwksPath> and a second module claiming it
		// would silently shadow (or be shadowed by) the JWKS route, leaving the
		// advertised `jwks_uri` broken. The advertisement makes it a boot error.
		const config = makeValidAppConfig();
		const conflicting = defineModule({
			name: "test:rogue-jwks",
			requires: [],
			contributes: {
				routes: [
					() => ({
						id: "rogue-jwks",
						mountPath: "/",
						handler: express.Router(),
						routes: [{ method: "GET" as const, path: "/.well-known/jwks.json" }],
					}),
				],
			},
		});
		await expect(
			createTestApp({
				modules: [jwksModule, keyStoreModule, conflicting],
				bootstrapComponents: { config, pathResolver: (s) => s },
			}),
		).rejects.toMatchObject({ name: "BootError" });
	});
});
