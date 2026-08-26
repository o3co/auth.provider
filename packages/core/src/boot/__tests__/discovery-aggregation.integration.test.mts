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
 * boot/__tests__/discovery-aggregation.integration.test.mts
 *
 * Integration tests for the `discoveryMetadata` contribution kind consumed by
 * `assembleApp`. Verifies the aggregator behaviour at the boot-pipeline level:
 *
 *   1. issuer configured + module contributions → core synthesizes the single
 *      `/.well-known/openid-configuration` document. The aggregator owns
 *      `issuer` (trailing-slash normalized) and
 *      `id_token_signing_alg_values_supported` (from `keyStore.algorithm`);
 *      module contributions supply issuer-relative endpoints + literal metadata,
 *      merged across modules.
 *   2. no `providerRoot` contribution → the discovery route is NOT mounted (no
 *      document is served). Since #266 an issuer is always configured, so the
 *      contribution is the only remaining gate at boot; the planner's own
 *      issuer guard is pinned directly.
 */

import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { DiscoveryDocumentError } from "../../discovery/buildDocument.mjs";
import { planDiscoveryRoute } from "../../discovery/planRoute.mjs";
import { createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { defineModule } from "../../modules/index.mjs";
import { createTestApp } from "../../testing/create-test-app.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { BootError } from "../types.mjs";

/** Inline module providing the `keyStore` component (HS256 → algorithm "HS256"). */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-discovery-agg!!!"),
	},
});

/**
 * A module contributing the OAuth-shaped slice of discovery metadata. Requires
 * `keyStore` to mirror the real oauth module's dependency — that requirement is
 * what materializes the keyStore component, from which the aggregator reads
 * `id_token_signing_alg_values_supported`.
 */
const oauthLikeModule = defineModule({
	name: "test:oauth-like",
	requires: ["keyStore"] as const,
	contributes: {
		discoveryMetadata: [
			() => ({
				// Provider root: the explicit "an OpenID Provider exists here" signal
				// that activates discovery aggregation.
				providerRoot: true,
				endpoints: {
					authorization_endpoint: "/oauth/authorize",
					token_endpoint: "/oauth/token",
				},
				metadata: {
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
				},
			}),
		],
	},
});

/** A module contributing only `jwks_uri` (the JWKS-owning slice). */
const jwksLikeModule = defineModule({
	name: "test:jwks-like",
	requires: [],
	contributes: {
		discoveryMetadata: [() => ({ endpoints: { jwks_uri: "/.well-known/jwks.json" } })],
	},
});

/**
 * A rogue module that contributes a route effectively serving
 * `GET /.well-known/openid-configuration` (mountPath "/" + advertised path).
 * It would be silently shadowed by the core-synthesized discovery route unless
 * the aggregator fails fast on the collision.
 */
const conflictingDiscoveryRouteModule = defineModule({
	name: "test:rogue-discovery-route",
	requires: [],
	contributes: {
		routes: [
			() => ({
				id: "rogue-discovery",
				mountPath: "/",
				handler: express.Router(),
				routes: [{ method: "GET" as const, path: "/.well-known/openid-configuration" }],
			}),
		],
	},
});

function withIssuer(issuer: string) {
	const config = makeValidAppConfig() as { oauth?: { jwt?: Record<string, unknown> } };
	return {
		...config,
		oauth: { ...config.oauth, jwt: { ...config.oauth?.jwt, issuer } },
	} as unknown as ReturnType<typeof makeValidAppConfig>;
}

describe("discoveryMetadata — core aggregation in assembleApp", () => {
	it("issuer configured → synthesizes /.well-known/openid-configuration from module contributions", async () => {
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		const res = await request(app).get("/.well-known/openid-configuration");
		expect(res.status).toBe(200);
		// Aggregator-owned fields.
		expect(res.body.issuer).toBe("https://auth.example.com");
		expect(res.body.id_token_signing_alg_values_supported).toEqual(["HS256"]);
		// Endpoints prefixed with the issuer, merged across both modules.
		expect(res.body.authorization_endpoint).toBe("https://auth.example.com/oauth/authorize");
		expect(res.body.token_endpoint).toBe("https://auth.example.com/oauth/token");
		expect(res.body.jwks_uri).toBe("https://auth.example.com/.well-known/jwks.json");
		// Literal metadata merged as-is.
		expect(res.body.response_types_supported).toEqual(["code"]);
		expect(res.body.subject_types_supported).toEqual(["public"]);

		await handle.dispose();
	});

	it("issuer set but no discoveryMetadata contributions → no route, no boot error", async () => {
		// A minimal composition that configures an issuer but wires no
		// discovery-contributing module is not participating in the discovery
		// aggregator at all — it must boot cleanly and simply not serve a
		// document (mirrors the pre-aggregator behaviour where discovery was the
		// oauth module's sole concern). The structural presence contract still
		// applies the moment ANY module contributes (see buildDocument tests).
		const handle = await createTestApp({
			modules: [keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		const res = await request(app).get("/.well-known/openid-configuration");
		expect(res.status).toBe(404);

		await handle.dispose();
	});

	it("issuer set + JWKS-only contribution (no providerRoot) → no route, no boot error", async () => {
		// A key-publishing deployment may mount jwksModule WITHOUT the full OAuth
		// suite, even with an issuer configured (jwks depends only on keyStore).
		// jwks contributes only the ancillary `jwks_uri` and does NOT set
		// `providerRoot`, so it does not by itself make the deployment an OpenID
		// Provider — discovery aggregation must not activate (else boot would fail
		// on the missing OAuth-required fields). Activation opts in only once a
		// contribution declares `providerRoot: true`.
		const handle = await createTestApp({
			modules: [jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		const res = await request(app).get("/.well-known/openid-configuration");
		expect(res.status).toBe(404);

		await handle.dispose();
	});

	it("fails fast when a module contributes a route colliding with the core discovery path", async () => {
		// The core-synthesized discovery route is a normal (synthetic) route
		// contribution advertising `GET /.well-known/openid-configuration`, so it
		// flows through `checkMaterialisedRouteCollisions` like any other route. A
		// module advertising the same effective method+path therefore fails the
		// boot fast as a duplicate — no special-casing, no silent shadowing.
		await expect(
			createTestApp({
				modules: [oauthLikeModule, jwksLikeModule, conflictingDiscoveryRouteModule, keyStoreModule],
				bootstrapComponents: {
					config: withIssuer("https://auth.example.com"),
					pathResolver: (s) => s,
				},
			}),
		).rejects.toMatchObject({ name: "BootError" });
	});

	it("issuer absent → the planner declines to synthesize the route", () => {
		// #266 made `oauth.jwt.issuer` required at the schema boundary, so this
		// state is no longer reachable through boot — every createTestApp config
		// carries one. The planner keeps its own guard for callers that reach it
		// with a config that never passed the schema, so it is pinned here
		// directly rather than through an unreachable boot fixture.
		const route = planDiscoveryRoute({
			components: { config: { oauth: { jwt: {} } } },
			registries: new Map(),
			routerFactory: () => express.Router(),
		});

		expect(route).toBeNull();
	});

	it("issuer + providerRoot contributed but jwks_uri missing → boot fails fast (BootError wrapping DiscoveryDocumentError)", async () => {
		// The migration's headline behavioral contract, pinned at the level it
		// actually executes. Once a contribution declares `providerRoot: true`,
		// the discovery planner invokes buildDiscoveryDocument at boot; a
		// composition that wires the OAuth provider surface + an issuer but omits
		// the jwks_uri-owning module fails the OIDC-required presence check. The
		// planner wraps the `DiscoveryDocumentError` in a `BootError`
		// (reason="discovery-document-invalid", cause=the original) so a discovery
		// misconfiguration surfaces through the same boot-failure taxonomy as every
		// other assembleApp error — `instanceof BootError` consumers don't miss it.
		const err = await createTestApp({
			// jwksLikeModule deliberately omitted — no module contributes `jwks_uri`.
			modules: [oauthLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		}).then(
			(handle) => {
				void handle.dispose();
				return null;
			},
			(e: unknown) => e,
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("discovery-document-invalid");
		expect((err as BootError).cause).toBeInstanceOf(DiscoveryDocumentError);
		expect(String((err as BootError).message)).toMatch(/jwks_uri/);
	});
});
