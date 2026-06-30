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
 *   2. issuer absent → the discovery route is NOT mounted (no document is
 *      served, mirroring the pre-aggregator issuer-gating that lived in the
 *      oauth module).
 */

import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { defineModule } from "../../modules/index.mjs";
import { createTestApp } from "../../testing/create-test-app.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";

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

	it("issuer set + JWKS-only contribution (no OAuth provider surface) → no route, no boot error", async () => {
		// A key-publishing deployment may mount jwksModule WITHOUT the full OAuth
		// suite, even with an issuer configured (jwks depends only on keyStore).
		// jwks contributes only the ancillary `jwks_uri`, which does NOT by itself
		// make the deployment an OpenID Provider — so it must not trigger discovery
		// aggregation (else boot would fail on the missing OAuth-required fields).
		// Aggregation opts in only once a provider-defining endpoint
		// (authorization_endpoint) is contributed.
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

	it("issuer absent → discovery route is not mounted (404)", async () => {
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: { config: makeValidAppConfig(), pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);

		const res = await request(app).get("/.well-known/openid-configuration");
		expect(res.status).toBe(404);

		await handle.dispose();
	});
});
