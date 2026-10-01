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
 * Integration tests for the `discoveryMetadata` contribution kind consumed by
 * `assembleApp`:
 *
 *   1. issuer configured + module contributions → core synthesizes the single
 *      `/.well-known/openid-configuration` document. The aggregator owns
 *      `issuer` (trailing-slash normalized) and
 *      `id_token_signing_alg_values_supported` (from `keyStore.algorithm`);
 *      modules supply issuer-relative endpoints and literal metadata, merged.
 *   2. no `providerRoot` contribution → no discovery route is mounted. An
 *      issuer is always configured, so the contribution is the only gate.
 *
 * The planner's handling of the values it is given is pinned in
 * [`discovery/__tests__/planRoute.test.mts`](../../discovery/__tests__/planRoute.test.mts).
 * This suite pins the wiring: that `assembleApp` reads the right values out
 * of its own world and converts the planner's error into its own taxonomy.
 */

import express from "express";
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { DiscoveryDocumentError } from "../../discovery/buildDocument.mjs";
import { createAsymmetricKeyStore, createSymmetricKeyStore } from "../../keys/KeyStore.mjs";
import { defineModule } from "../../modules/index.mjs";
import { createTestApp } from "../../testing/create-test-app.mjs";
import { makeValidAppConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestHttpSettings } from "../../testing/slots/httpSettings.mjs";
import { createTestOAuthTokenSettings } from "../../testing/slots/oauthTokenSettings.mjs";
import { BootError } from "../types.mjs";

/** Inline module providing the `keyStore` component (HS256 → algorithm "HS256"). */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-discovery-agg!!!"),
	},
});

/**
 * The same slot filled with an ES256 store, so the algorithm the document
 * advertises is one no fixture hard-codes. Every other discovery fixture is
 * HS256, where `assembleApp`'s `keyStore.algorithm` → `signingAlgs`
 * derivation cannot be told from the literal `["HS256"]`.
 */
const es256KeyStoreModule = defineModule({
	name: "test:key-store-es256",
	provides: {
		keyStore: async () => {
			const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
			return createAsymmetricKeyStore({
				algorithm: "ES256",
				kid: "es256-discovery",
				privateKeyPem: await exportPKCS8(privateKey),
				publicKeyPem: await exportSPKI(publicKey),
			});
		},
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

	it("advertises the algorithm the key store in the slot actually uses, not HS256", async () => {
		// `assembleApp` derives `signingAlgs` from `keyStore.algorithm` and hands
		// it to the planner. The planner's unit test covers the parameter; this
		// covers the derivation.
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, es256KeyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		const res = await request(app).get("/.well-known/openid-configuration");

		expect(res.status).toBe(200);
		expect(res.body.id_token_signing_alg_values_supported).toEqual(["ES256"]);

		await handle.dispose();
	});

	it("also serves the RFC 8414 path with a byte-identical document", async () => {
		// Some clients probe /.well-known/oauth-authorization-server first and
		// fall back to OIDC discovery; some never fall back. One handler serves
		// both, so bodies and headers cannot differ.
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		const oidc = await request(app).get("/.well-known/openid-configuration");
		const oauth = await request(app).get("/.well-known/oauth-authorization-server");
		expect(oauth.status).toBe(200);
		expect(oauth.text).toBe(oidc.text);
		expect(oauth.headers["content-type"]).toBe(oidc.headers["content-type"]);
		expect(oauth.headers["cache-control"]).toBe(oidc.headers["cache-control"]);
		// RFC 8414 §3.3: the document's issuer equals the identifier the client
		// formed the URL from, exactly.
		expect(oauth.body.issuer).toBe("https://auth.example.com");

		await handle.dispose();
	});

	it("a path-bearing issuer: RFC 8414 inserts the well-known string, OIDC appends it", async () => {
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com/tenant-a"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		const inserted = await request(app).get("/.well-known/oauth-authorization-server/tenant-a");
		expect(inserted.status).toBe(200);
		expect(inserted.body.issuer).toBe("https://auth.example.com/tenant-a");
		const appended = await request(app).get("/tenant-a/.well-known/openid-configuration");
		expect(appended.status).toBe(200);
		expect(appended.text).toBe(inserted.text);
		// The root RFC 8414 form names a different issuer and is not served.
		expect((await request(app).get("/.well-known/oauth-authorization-server")).status).toBe(404);

		await handle.dispose();
	});

	it("serves the document on the issuer of the oauthTokenSettings the composition holds, and lets CORS read it there", async () => {
		// The configuration names the issuer without a path; the slot the oauth
		// module provides names it under one, and the slot is what is read.
		const config = withIssuer("https://auth.example.com");
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config,
				pathResolver: (s) => s,
				httpSettings: createTestHttpSettings({ allowedOrigins: ["https://app.example"] }),
				oauthTokenSettings: createTestOAuthTokenSettings({
					issuer: "https://auth.example.com/tenant-a",
				}),
			},
		});
		const app = express();
		app.use(handle.router);

		const inserted = await request(app).get("/.well-known/oauth-authorization-server/tenant-a");
		expect(inserted.status).toBe(200);
		expect(inserted.body.issuer).toBe("https://auth.example.com/tenant-a");
		expect(inserted.body.token_endpoint).toBe("https://auth.example.com/tenant-a/oauth/token");
		const appended = await request(app)
			.get("/tenant-a/.well-known/openid-configuration")
			.set("Origin", "https://app.example");
		expect(appended.status).toBe(200);
		expect(appended.headers["access-control-allow-origin"]).toBe("https://app.example");

		await handle.dispose();
	});

	it("builds a provider of oauthTokenSettings that nothing requires, and serves the document on its issuer", async () => {
		const lazySettings = defineModule({
			name: "test:lazy-token-settings",
			provides: {
				oauthTokenSettings: () =>
					createTestOAuthTokenSettings({ issuer: "https://auth.example.com/tenant-a" }),
			},
		});
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule, lazySettings],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		const inserted = await request(app).get("/.well-known/oauth-authorization-server/tenant-a");
		expect(inserted.status).toBe(200);
		expect(inserted.body.issuer).toBe("https://auth.example.com/tenant-a");

		await handle.dispose();
	});

	it("refuses a provider of oauthTokenSettings that answers undefined, naming the slot, rather than serving on the configuration's issuer", async () => {
		const undefinedSettings = defineModule({
			name: "test:undefined-token-settings",
			provides: { oauthTokenSettings: () => undefined as never },
		});
		const booting = createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule, undefinedSettings],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		await expect(booting).rejects.toThrow(/oauthTokenSettings/);
	});

	it("refuses an oauthTokenSettings without an issuer, naming the member, rather than serving on the configuration's", async () => {
		// A slot the composition holds is read whole: a member it lacks is not
		// taken from the configuration beside it.
		const { issuer: _dropped, ...withoutIssuer } = createTestOAuthTokenSettings();
		const booting = createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
				oauthTokenSettings: withoutIssuer as never,
			},
		});
		await expect(booting).rejects.toThrow(/oauthTokenSettings\.issuer/);
	});

	it("an issuer path is a literal, not a route pattern: metacharacters boot and serve", async () => {
		// Express 5 parses a route string with path-to-regexp, where `+`, `*`,
		// `(`, `)`, `:` and `{}` are syntax. An issuer is a URL, and those
		// characters are legal in its path: passing it verbatim to
		// `router.get` either fails the boot or matches the wrong requests.
		for (const tenant of ["tenant+blue", "tenant(a)", "a*b", "x:y", "g{h}"]) {
			const issuer = `https://auth.example.com/${tenant}`;
			const handle = await createTestApp({
				modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
				bootstrapComponents: { config: withIssuer(issuer), pathResolver: (s) => s },
			});
			const app = express();
			app.use(handle.router);

			const inserted = await request(app).get(`/.well-known/oauth-authorization-server/${tenant}`);
			expect(inserted.status).toBe(200);
			expect(inserted.body.issuer).toBe(issuer);
			const appended = await request(app).get(`/${tenant}/.well-known/openid-configuration`);
			expect(appended.status).toBe(200);
			expect(appended.text).toBe(inserted.text);

			await handle.dispose();
		}
	});

	it("matches the advertised path as a literal, not a pattern, and still with a trailing slash", async () => {
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com/a*b"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);

		// The `*` is a character of this tenant's name, so it matches that
		// name and not the tenant next door.
		expect(
			(await request(app).get("/.well-known/oauth-authorization-server/anything")).status,
		).toBe(404);
		// A trailing slash still reaches it, as under Express's non-strict
		// routing.
		expect((await request(app).get("/.well-known/oauth-authorization-server/a*b/")).status).toBe(
			200,
		);

		await handle.dispose();
	});

	it("answers HEAD, and passes a POST on to the rest of the app", async () => {
		const handle = await createTestApp({
			modules: [oauthLikeModule, jwksLikeModule, keyStoreModule],
			bootstrapComponents: {
				config: withIssuer("https://auth.example.com"),
				pathResolver: (s) => s,
			},
		});
		const app = express();
		app.use(handle.router);
		app.use((_req, res) => res.status(404).json({ error: "not_found" }));

		expect((await request(app).head("/.well-known/openid-configuration")).status).toBe(200);
		// A POST to the metadata path is not this route's business; it passes
		// through, as it would past a `router.get` route.
		const posted = await request(app).post("/.well-known/oauth-authorization-server");
		expect(posted.status).toBe(404);
		expect(posted.body.error).toBe("not_found");

		await handle.dispose();
	});

	it("issuer set but no discoveryMetadata contributions → no route, no boot error", async () => {
		// A composition that configures an issuer but wires no
		// discovery-contributing module boots cleanly and serves no document.
		// The structural presence contract applies the moment ANY module
		// contributes (see buildDocument tests).
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
		// A key-publishing deployment may mount jwksModule WITHOUT the OAuth
		// suite (jwks depends only on keyStore). jwks contributes only
		// `jwks_uri` and does not set `providerRoot`, so aggregation must not
		// activate, or boot would fail on the missing OAuth-required fields.
		// Only a contribution declaring `providerRoot: true` activates it.
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
		// The core-synthesized discovery route is a (synthetic) route
		// contribution advertising `GET /.well-known/openid-configuration`, so it
		// goes through `checkMaterialisedRouteCollisions` like any other route: a
		// module advertising the same method+path fails boot as a duplicate
		// instead of being silently shadowed.
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

	it("issuer + providerRoot contributed but jwks_uri missing → boot fails fast (BootError wrapping DiscoveryDocumentError)", async () => {
		// Once a contribution declares `providerRoot: true`, the planner runs
		// buildDiscoveryDocument at boot, so a composition with the OAuth surface
		// and an issuer but no jwks_uri-owning module fails the OIDC-required
		// presence check. The `DiscoveryDocumentError` arrives wrapped in a
		// `BootError` (reason="discovery-document-invalid", cause=the original),
		// the taxonomy of every other assembleApp error.
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
		// The whole shape of `assembleApp`'s conversion, not only the fields an
		// operator reads first.
		const cause = (err as BootError).cause as DiscoveryDocumentError;
		expect((err as BootError).message).toBe(`assembleApp: ${cause.message}`);
		expect((err as BootError).stage).toBe("assembleApp");
		expect((err as BootError).details).toEqual({
			reason: "discovery-document-invalid",
			detail: cause.message,
		});
	});
});
