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

import { createSecretKey } from "node:crypto";
import {
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createAsymmetricKeyStore,
	createSymmetricKeyStore,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	defineModule,
	type FederationProvider,
	type FederationTokenStore,
	type GrantHandler,
	jwksModule,
	type Module,
	memoryAccessTokenDenylistModule,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	type RateLimiter,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { exportPKCS8, exportSPKI, generateKeyPair, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthModule } from "#/module.mjs";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";
import { oauthSessionModule } from "#/oauthSession.mjs";
import { createMockLogger } from "./_helpers/mockLogger.mjs";
import { withGrants, withOauthCaptures } from "./_helpers/sections.mjs";

/**
 * A federation that satisfies the `FederationProvider` contract, with whatever
 * capability the case under test adds: these routes read a provider the boot
 * planner could actually have handed them.
 */
const federationBase = (name: string) => ({
	name,
	scope: ["openid"] as readonly string[],
	buildAuthorizationUrl: () => new URL(`https://${name}.example/auth`),
	exchangeCode: async () => ({
		issuer: `https://${name}.example`,
		sub: "sub-1",
		expiresAt: null,
	}),
});

// ---------------------------------------------------------------------------
// Shared test-only stubs
// ---------------------------------------------------------------------------

const fakeClientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const fakeCodeRepository: CodeRepository = {
	// Code requires client_id + redirect_uri.
	createCode: async () => ({
		code: "fake-code",
		client_id: "client1",
		redirect_uri: "https://rp.example/cb",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/** Inline module that satisfies `requires: ["clientRepository"]`. */
const clientRepositoryModule = defineModule({
	name: "test:client-repository",
	provides: {
		clientRepository: () => fakeClientRepository,
	},
});

/** Inline module that satisfies `requires: ["codeRepository"]`. */
const codeRepositoryModule = defineModule({
	name: "test:code-repository",
	provides: {
		codeRepository: () => fakeCodeRepository,
	},
});

/** Inline module that satisfies `requires: ["keyStore"]`. */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-oauth-module!!!!!"),
	},
});

/**
 * A stand-in authorization_code grant: what makes `oauthModule` serve
 * `/authorize` and name it in discovery. Never dispatched to.
 */
const authorizationCodeGrantModule = defineModule({
	name: "test:authorization-code-grant",
	contributes: {
		grants: {
			authorization_code: (): GrantHandler => ({
				handle: async () => {
					throw new Error("the stand-in grant is never dispatched to");
				},
			}),
		},
	},
});

// The JWKS route refuses to publish an empty key set, so the
// discovery/JWKS path-agreement tests below need a keystore that actually has
// public key material. EdDSA is the shipped default.
const eddsaPair = await generateKeyPair("EdDSA", { extractable: true });
const eddsaKeyStore = await createAsymmetricKeyStore({
	algorithm: "EdDSA",
	kid: "oauth-module-test",
	privateKeyPem: await exportPKCS8(eddsaPair.privateKey),
	publicKeyPem: await exportSPKI(eddsaPair.publicKey),
});

const asymmetricKeyStoreModule = defineModule({
	name: "test:key-store-asymmetric",
	provides: {
		keyStore: () => eddsaKeyStore,
	},
});

// Note: grantHandlerResolver is a SYNTHETIC key — the boot planner injects it
// automatically from collected grants. Do NOT provide it from a module.

// ---------------------------------------------------------------------------
// Module manifest structural tests (static, no createTestApp needed)
// ---------------------------------------------------------------------------

describe("oauthModule — manifest shape", () => {
	it("has name 'oauth'", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		expect(module.name).toBe("oauth");
	});

	it("declares a configSchema for boot-time config validation", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		expect(module.configSchema).toBeDefined();
	});

	it("configSchema rejects a config missing endpoints.login.url", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const schema = module.configSchema;
		if (!schema) throw new Error("configSchema must be defined");
		// Core's schema requires a string there; oauthConfigSchema requires it
		// too, non-empty, so boot fails before /authorize is hit.
		const result = schema.safeParse({ endpoints: { login: {} } });
		expect(result.success).toBe(false);
	});

	it("configSchema rejects an empty endpoints.login.url", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const schema = module.configSchema;
		if (!schema) throw new Error("configSchema must be defined");
		const result = schema.safeParse({ endpoints: { login: { url: "" } } });
		expect(result.success).toBe(false);
	});

	it("configSchema accepts a non-empty endpoints.login.url", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const schema = module.configSchema;
		if (!schema) throw new Error("configSchema must be defined");
		const result = schema.safeParse({ endpoints: { login: { url: "/login" } } });
		expect(result.success).toBe(true);
	});

	it.each([
		["a path", "/login?redirect_to=https://x"],
		["an absolute URL", "https://login.example/signin?tenant=x&redirect_to=https%3A%2F%2Fx"],
		["a name written percent-encoded", "/login?redirect%5Fto=x"],
		["a name with no value", "/login?tenant=x&redirect_to"],
		// The rule reads the query as the redirect writes it — the text before
		// any `#`, after the first `?` — so a URL `URL` cannot parse is held to
		// it too: the redirect would append a second one all the same.
		["a URL that does not parse", "http://[::1/login?redirect_to=x"],
		["a URL that does not parse, with a fragment", "http://[::1/login?tenant=x&redirect_to=y#z"],
	])(
		"configSchema refuses %s whose own query carries redirect_to, naming the key: the provider adds it",
		(_label, url) => {
			const schema = oauthModule({ config: makeValidAppConfig() }).configSchema;
			if (!schema) throw new Error("configSchema must be defined");
			const result = schema.safeParse({ endpoints: { login: { url } } });
			expect(result.success).toBe(false);
			const issue = result.error?.issues[0];
			expect(issue?.path).toEqual(["endpoints", "login", "url"]);
			expect(issue?.message).toContain('"redirect_to"');
			expect(issue?.message).toContain("the provider adds");
		},
	);

	it.each([
		["a query of its own", "/login?tenant=x"],
		["an absolute URL with a query", "https://login.example/signin?tenant=x"],
		["redirect_to inside the fragment alone", "/login#redirect_to=https://x"],
		["a query, and redirect_to inside the fragment", "/login?tenant=x#redirect_to=y"],
		["a name that differs in case", "/login?Redirect_To=x"],
		["a longer name", "/login?redirect_to_after=x"],
		["a URL that does not parse, without redirect_to", "http://[::1/login?tenant=x"],
		["a `?` inside the fragment alone", "/login#a?redirect_to=x"],
	])("configSchema accepts a login URL with %s", (_label, url) => {
		const schema = oauthModule({ config: makeValidAppConfig() }).configSchema;
		if (!schema) throw new Error("configSchema must be defined");
		expect(schema.safeParse({ endpoints: { login: { url } } }).success).toBe(true);
	});

	it("includes only oauth-endpoints when issuer is absent (JWKS moved to core jwksModule)", () => {
		const base = makeValidAppConfig();
		// No issuer set: only oauth-endpoints is contributed. JWKS is not an
		// oauth contribution; core's jwksModule owns it.
		const module = oauthModule({ config: base });
		const routes = module.contributes?.routes;
		expect(Array.isArray(routes)).toBe(true);
		expect((routes as unknown[]).length).toBe(1);
	});

	it("contributes a single oauth-endpoints route regardless of issuer (discovery is core-aggregated)", () => {
		// Discovery is not an oauth ROUTE: oauth contributes a
		// `discoveryMetadata` slice, which core's assembleApp aggregates into
		// `/.well-known/openid-configuration`.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" } },
		};
		const module = oauthModule({ config });
		const routes = module.contributes?.routes;
		expect(Array.isArray(routes)).toBe(true);
		expect((routes as unknown[]).length).toBe(1);
	});

	it("contributes a single discoveryMetadata factory (issuer-independent; core gates emission)", () => {
		const config = makeValidAppConfig();
		const module = oauthModule({ config });
		const discoveryMetadata = module.contributes?.discoveryMetadata;
		expect(Array.isArray(discoveryMetadata)).toBe(true);
		expect((discoveryMetadata as unknown[]).length).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// createTestApp integration tests (boot + inspect)
// ---------------------------------------------------------------------------

describe("oauthModule — createTestApp boot failure", () => {
	it("fails boot with config-validation-failed when endpoints.login.url is missing", async () => {
		const { BootError } = await import("@o3co/auth-provider-core");
		const base = makeValidAppConfig();
		const config = {
			...base,
			endpoints: {
				...base.endpoints,
				login: {}, // tighten path: drop the url that valid-config now provides
			},
		};
		await expect(
			createTestApp({
				modules: [
					oauthModule({ config }),
					// oauthModule mounts /oauth/revoke, so the boot validator requires a
					// denylist behind it. Memory is right here — one process, one test.
					memoryAccessTokenDenylistModule,
					clientRepositoryModule,
					codeRepositoryModule,
					keyStoreModule,
				],
				bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "config-validation-failed",
		} satisfies Partial<InstanceType<typeof BootError>>);
	});

	const bootWithLoginUrl = (url: string) => {
		const base = makeValidAppConfig();
		const config = { ...base, endpoints: { ...base.endpoints, login: { url } } };
		return createTestApp({
			modules: [
				oauthModule({ config }),
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
	};

	it.each([
		["a path", "/login?redirect_to=https://x"],
		["an absolute URL", "https://login.example/signin?redirect_to=https%3A%2F%2Fx"],
	])(
		"fails boot when endpoints.login.url is %s carrying redirect_to, naming the key",
		async (_label, url) => {
			let refusal: unknown;
			try {
				const handle = await bootWithLoginUrl(url);
				await handle.dispose();
			} catch (err) {
				refusal = err;
			}
			expect(refusal).toMatchObject({ name: "BootError", reason: "config-validation-failed" });
			const issues = (refusal as { details?: { issues?: { path: unknown; message: string }[] } })
				.details?.issues;
			expect(issues).toContainEqual(
				expect.objectContaining({
					path: ["endpoints", "login", "url"],
					message: expect.stringMatching(/"redirect_to".*the provider adds/),
				}),
			);
		},
	);

	it.each([
		["a query of its own", "/login?tenant=x"],
		["redirect_to inside the fragment alone", "/login#redirect_to=https://x"],
	])("boots when endpoints.login.url carries %s", async (_label, url) => {
		const handle = await bootWithLoginUrl(url);
		await handle.dispose();
	});
});

describe("oauthModule — createTestApp route inspection", () => {
	it("contributes no oidc-discovery route even with an issuer; core mounts discovery from aggregated metadata", async () => {
		// Core's assembleApp mounts discovery from the aggregated
		// `discoveryMetadata` collector, so it never appears in the inspected
		// route ids. jwksModule is co-installed because it owns `jwks_uri`;
		// without it boot fails the presence contract.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" } },
		};
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const routeIds = handle.inspect.routes.map((r) => r.contribution.id);
		expect(routeIds).toContain("oauth-endpoints");
		expect(routeIds).not.toContain("oidc-discovery");
		await handle.dispose();
	});

	it("oauth-endpoints is mounted at /oauth", async () => {
		const config = makeValidAppConfig();
		// jwksModule is co-installed because every config carries an issuer, so
		// discovery is always active and needs a module owning `jwks_uri`.
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const oauthRoute = handle.inspect.routes.find((r) => r.contribution.id === "oauth-endpoints");
		expect(oauthRoute?.contribution.mountPath).toBe("/oauth");
		await handle.dispose();
	});

	it("core serves the spec-fixed /.well-known/openid-configuration when oauth + jwks + issuer compose", async () => {
		// End-to-end: oauth contributes its endpoints + metadata, jwks contributes
		// `jwks_uri`, core aggregates and mounts the document at the spec-fixed
		// path (no path-doubling). Probes the actual path.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" },
			},
		};
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const res = await request(app).get("/.well-known/openid-configuration");
		expect(res.status).toBe(200);
		expect(res.body.issuer).toBe("https://auth.example.com");
		await handle.dispose();
	});
});

describe("oauthModule — the acr table in the served discovery document", () => {
	const acrValues = {
		"urn:example:pwd": ["pwd"],
		"urn:example:mfa": ["pwd", "mfa"],
	};
	const acrConfig = (federations: Record<string, unknown> = {}) => {
		const base = makeValidAppConfig();
		return {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" },
				authorize: { acrValues },
			},
			federations,
		} as ReturnType<typeof makeValidAppConfig>;
	};
	/** A federation, contributed as a federation package's module contributes one. */
	const googleFederationModule = defineModule({
		name: "test:google-federation-acr",
		contributes: {
			federations: { google: () => federationBase("google") },
			federationRedirectPolicies: {
				google: () => ({
					validateRedirect: () => ({ ok: true as const, value: undefined }),
					resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
				}),
			},
		} as never,
	});
	const boot = async (
		extraModules: readonly Parameters<typeof createTestApp>[0]["modules"][number][],
		federations: Record<string, unknown> = {},
	) => {
		const config = acrConfig(federations);
		const logger = createMockLogger();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				authorizationCodeGrantModule,
				asymmetricKeyStoreModule,
				...extraModules,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s, logger },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		await handle.dispose();
		const lines = (level: ReturnType<typeof vi.fn>) =>
			level.mock.calls.filter((call) => call[1] === "acr_value_unsatisfiable");
		return { body, logger, lines };
	};

	/**
	 * What an enabled federation needs beside it (boot refuses one without
	 * them): the session stores, the federation-token store and family
	 * revocation.
	 */
	const federationStores = [
		memorySessionStoresModule,
		memoryFederationTokenStoreModule,
		memoryRefreshTokenFamilyStoreModule,
		defaultRefreshTokenFamilyRevocationModule,
	];

	it("advertises only what a login this composition performs can meet, and says once at boot what it dropped", async () => {
		const { body, logger, lines } = await boot([]);
		expect(body.acr_values_supported).toEqual(["urn:example:pwd"]);
		// `mfa.mode` is "off" (core's default): an entry that only a second
		// factor would meet is not a misconfiguration, so the line is info.
		expect(lines(logger.info)).toEqual([
			[{ acr: "urn:example:mfa", unproducible: ["mfa"] }, "acr_value_unsatisfiable"],
		]);
		expect(lines(logger.warn)).toEqual([]);
	});

	it("drops what only an upstream IdP could assert while the installed federation does not trust its amr", async () => {
		// The default: an upstream `mfa` is kept apart from the session's `amr`
		// and meets no `acr`, so the entry is one nothing installed can meet —
		// for an installed, enabled federation that says nothing of its trust.
		// (Boot parses the `federations` section core's schema declares
		// whenever it is present, so an entry states `enabled`.)
		const { body, logger, lines } = await boot([googleFederationModule, ...federationStores], {
			google: { enabled: true },
		});
		expect(body.acr_values_supported).toEqual(["urn:example:pwd"]);
		expect(lines(logger.info)).toEqual([
			[{ acr: "urn:example:mfa", unproducible: ["mfa"] }, "acr_value_unsatisfiable"],
		]);
		expect(lines(logger.warn)).toEqual([]);
	});

	it("advertises every entry, and drops none, while an installed, enabled federation trusts its upstream amr", async () => {
		const { body, logger, lines } = await boot([googleFederationModule, ...federationStores], {
			google: { enabled: true, trustUpstreamAmr: true },
		});
		expect(body.acr_values_supported).toEqual(["urn:example:pwd", "urn:example:mfa"]);
		expect(lines(logger.info)).toEqual([]);
		expect(lines(logger.warn)).toEqual([]);
	});

	it("counts no installed federation whose section is disabled as trusted: nothing can sign a user in through it", async () => {
		const { body, logger, lines } = await boot([googleFederationModule], {
			google: { enabled: false, trustUpstreamAmr: true },
		});
		expect(body.acr_values_supported).toEqual(["urn:example:pwd"]);
		expect(lines(logger.info)).toEqual([
			[{ acr: "urn:example:mfa", unproducible: ["mfa"] }, "acr_value_unsatisfiable"],
		]);
	});

	it("refuses to compose when a federation's trustUpstreamAmr is given but unusable", async () => {
		// Boot's parse refuses it by path, before the acr table is
		// read; the reader's own refusal, for a configuration handed to it
		// outside boot, is pinned beside it in core.
		await expect(
			boot([googleFederationModule], { google: { enabled: false, trustUpstreamAmr: "yes" } }),
		).rejects.toThrow(/federations\.google\.trustUpstreamAmr: /);
	});
});

// ---------------------------------------------------------------------------
// Discovery <-> JWKS path agreement (presence + config-drift contract).
//
// JWKS is contributed by core's `jwksModule`, oidc-discovery (which
// advertises `jwks_uri`) by oauth, so an issuer-enabled composition MUST
// co-install both or discovery publishes a dangling `jwks_uri`. The
// advertised `jwks_uri` must resolve to a mounted JWKS route, including under
// a `jwks.path` override (both resolve it via the shared `resolveJwksPath`).
// ---------------------------------------------------------------------------

describe("oauthModule + jwksModule — discovery/JWKS path agreement", () => {
	function issuerConfig(extraJwt: Record<string, unknown> = {}) {
		const base = makeValidAppConfig();
		return {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com", ...extraJwt },
			},
		} as ReturnType<typeof makeValidAppConfig>;
	}

	it("advertised jwks_uri resolves to a mounted JWKS route (default path)", async () => {
		const config = issuerConfig();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				// Asymmetric: the JWKS route refuses to publish an
				// empty key set, so "resolves to a mounted route" is only
				// observable with a keystore that has public material.
				asymmetricKeyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const disco = await request(app).get("/.well-known/openid-configuration");
		expect(disco.status).toBe(200);
		const jwksPath = new URL(disco.body.jwks_uri as string).pathname;
		expect(jwksPath).toBe("/.well-known/jwks.json");
		const res = await request(app).get(jwksPath);
		expect(res.status).toBe(200);
		expect(Array.isArray(res.body.keys)).toBe(true);
		expect(res.body.keys).toHaveLength(1);
		await handle.dispose();
	});

	it("aggregated discovery document matches the golden field set (no-logout composition)", async () => {
		// Whole-document guard: with oauth + jwks + issuer (and no session stores →
		// logout omitted), the assembled `/.well-known/openid-configuration`
		// carries EXACTLY these fields. `toEqual` is the point: a field added by
		// a future contribution has to be argued for here rather than appearing in
		// the served document unnoticed.
		//
		// `grant_types_supported` is `[]` because this composition registers no
		// grant module: POST /oauth/token answers `unsupported_grant_type` for
		// every value. Omitting the field would claim `authorization_code` +
		// `implicit` (RFC 8414 §2's default). With no authorization_code grant
		// there is no authorization endpoint: none is named, no response type
		// is listed, and nothing a client sends to it is advertised.
		const config = issuerConfig();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		const iss = "https://auth.example.com";
		expect(body).toEqual({
			issuer: iss,
			token_endpoint: `${iss}/oauth/token`,
			userinfo_endpoint: `${iss}/oauth/userinfo`,
			jwks_uri: `${iss}/.well-known/jwks.json`,
			introspection_endpoint: `${iss}/oauth/introspect`,
			// /oauth/revoke is always mounted, and this composition wires the
			// memory denylist, so it can actually revoke something.
			revocation_endpoint: `${iss}/oauth/revoke`,
			response_types_supported: [],
			subject_types_supported: ["public"],
			// keyStoreModule signs HS256, so the aggregator advertises exactly that.
			id_token_signing_alg_values_supported: ["HS256"],
			scopes_supported: ["openid", "profile", "email", "groups"],
			grant_types_supported: [],
			// private_key_jwt on every client-authenticated endpoint, with
			// the assertion algorithms it accepts (RFC 8414 §2) — advertised only
			// where a replay seen-set can record the assertion's single-use
			// `jti`, which this composition does not wire.
			token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
			revocation_endpoint_auth_methods_supported: [
				"client_secret_basic",
				"client_secret_post",
				"none",
			],
		});
		await handle.dispose();
	});

	it('omits revocation_endpoint end-to-end under oauth.revocation.accessToken = "unsupported" with no other revocation capability', async () => {
		// Declaring the access-token capability absent lets a deployment boot
		// with no `accessTokenDenylist` (core's boot validator returns early on
		// `"unsupported"`). With no `refreshTokenFamilyRevocation` either,
		// `POST /oauth/revoke` is mounted and revokes nothing, so the served
		// document must not name it. End-to-end because the same config must
		// both survive the boot validator AND produce a document without the
		// endpoint: two layers reading one key the same way.
		const base = issuerConfig();
		const config = {
			...base,
			// `subject: "unsupported"` rides along because this override replaces
			// the whole `revocation` object, and the fixture's declaration
			// goes with it. This composition wires no subject stores
			// either, so the declaration is honest.
			oauth: {
				...base.oauth,
				revocation: { accessToken: "unsupported", subject: "unsupported" },
			},
		} as ReturnType<typeof makeValidAppConfig>;
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// Deliberately no memoryAccessTokenDenylistModule — that is the point.
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const { status, body } = await request(app).get("/.well-known/openid-configuration");
		expect(status).toBe(200);
		expect(body).not.toHaveProperty("revocation_endpoint");
		expect(body).not.toHaveProperty("revocation_endpoint_auth_methods_supported");
		// The rest of the document is unaffected — this gate is narrow.
		expect(body.introspection_endpoint).toBe("https://auth.example.com/oauth/introspect");
		await handle.dispose();
	});

	it("advertises exactly the grant types the config actually enabled", async () => {
		// End-to-end guard on the anti-drift property: `grant_types_supported` is
		// read off the same `grantHandlerResolver` `/oauth/token` dispatches
		// against, so a grant whose switch is off cannot be advertised, and one
		// switched on cannot be missed.
		const config = withGrants(issuerConfig(), {
			authorizationCode: true,
			refreshToken: true,
			// Left off on purpose — it must not appear below.
			clientCredentials: false,
		}) as ReturnType<typeof makeValidAppConfig>;
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				oauthAuthorizationModule({ config }),
				memoryAccessTokenDenylistModule,
				// The refresh_token grant, on here, refuses to boot without its families.
				memoryRefreshTokenFamilyStoreModule,
				defaultRefreshTokenFamilyRotationModule,
				defaultRefreshTokenFamilyRevocationModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		expect(body.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
		expect(body.grant_types_supported).not.toContain("client_credentials");
		// RFC 8414 §2's omitted default is `["authorization_code", "implicit"]`.
		// The field exists precisely so `implicit` stops being implied.
		expect(body.grant_types_supported).not.toContain("implicit");
		await handle.dispose();
	});

	it("honors jwks.path for BOTH the advertised jwks_uri and the mounted route", async () => {
		const config = { ...issuerConfig(), jwks: { path: "/keys/jwks.json" } };
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				asymmetricKeyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const disco = await request(app).get("/.well-known/openid-configuration");
		expect(disco.body.jwks_uri).toBe("https://auth.example.com/keys/jwks.json");
		const jwksPath = new URL(disco.body.jwks_uri as string).pathname;
		expect((await request(app).get(jwksPath)).status).toBe(200);
		// The default path is not served under the override.
		expect((await request(app).get("/.well-known/jwks.json")).status).toBe(404);
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Behavioral: grant dispatch via router
// The HTTP probe builds a full express app to verify createOAuthRouter wires
// correctly through the deps injected by the boot planner.
// ---------------------------------------------------------------------------

describe("oauthModule — behavioral: rateLimiter + auditSink forwarding", () => {
	it("forwards rateLimiter and auditSink into oauth routes (rate limit returns 429)", async () => {
		const SECRET = "test-secret-at-least-32-chars!!";

		const rateLimiter: RateLimiter = {
			kind: "spy",
			check: vi.fn().mockResolvedValue({ allowed: false, reason: "limit:token" }),
		};
		const events: AuditEvent[] = [];
		const auditSink: AuditSink = {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		};

		const rateLimiterModule = defineModule({
			name: "test:rate-limiter",
			provides: { rateLimiter: () => rateLimiter },
		});
		const auditSinkModule = defineModule({
			name: "test:audit-sink",
			provides: { auditSink: () => auditSink },
		});
		const keyStoreWithSecret = defineModule({
			name: "test:key-store-secret",
			provides: { keyStore: () => createSymmetricKeyStore(SECRET) },
		});

		const base = makeValidAppConfig();
		const config = { ...base };

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreWithSecret,
				rateLimiterModule,
				auditSinkModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});

		// Mount the routes onto an express app for HTTP probing
		const app = express();
		app.set("trust proxy", 1);
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		const res = await request(app).post("/oauth/token").send({ grant_type: "password" });

		// rateLimiter was forwarded and invoked by the route
		expect(rateLimiter.check).toHaveBeenCalled();
		expect(res.status).toBe(429);

		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Behavioral: federation logout — deps.federationProviders typed slot
//
// oauthModule reads federationProviders from typed deps, supplied at boot via
// the DI graph, not through a lazy () => ctx.federationProviders closure.
// ---------------------------------------------------------------------------

describe("oauthModule — federation logout via typed deps", () => {
	it("federation logout works when federationProviders is supplied via module", async () => {
		const SECRET = "test-secret-at-least-32-chars!!";
		const secretKey = createSecretKey(Buffer.from(SECRET));

		const accessToken = await new SignJWT({ sub: "u-1", sid: "sid-1", family_id: "fam-1" })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
			.setIssuer("https://auth.example.com")
			.setExpirationTime("1h")
			.setIssuedAt()
			.sign(secretKey);

		const session: UserSession = {
			sid: "sid-1",
			sub: "u-1",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 3_600_000),
			claims: {},
			amr: undefined,
			authentication: undefined,
		};

		const sessionStore: UserSessionStore = {
			kind: "memory",
			create: vi.fn(),
			get: vi.fn().mockResolvedValue(session),
			delete: vi.fn(),
		};
		const sessionRPRegistry: SessionRPRegistry = {
			kind: "memory",
			registerRP: vi.fn(async () => {}),
			listRPs: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFamilyIndex: SessionFamilyIndex = {
			kind: "memory",
			addFamilyId: vi.fn(async () => {}),
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFederationIndex: SessionFederationIndex = {
			kind: "memory",
			addFederation: vi.fn(async () => {}),
			listFederations: vi.fn(async () => ["google"]),
			removeFederation: vi.fn(async () => {}),
			removeBySid: vi.fn(async () => {}),
		};
		const fedTokenStore: FederationTokenStore = {
			kind: "memory",
			attach: vi.fn(),
			get: vi.fn().mockResolvedValue({ idToken: "id-token-hint" }),
			update: vi.fn(),
			removeBySid: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			isFamilyRevoked: vi.fn(async () => false),
			revokeFamily: vi.fn(),
		};

		const endSessionUrl = new URL("https://accounts.google.com/logout?hint=id-token-hint");
		const googleProvider: FederationProvider & {
			endSession: (req: unknown) => Promise<{ url: URL; method: "GET" }>;
		} = {
			...federationBase("google"),
			endSession: vi.fn().mockResolvedValue({ url: endSessionUrl, method: "GET" }),
		};

		// Modules providing the optional stores
		const userSessionStoreModule = defineModule({
			name: "test:user-session-store",
			provides: { userSessionStore: () => sessionStore },
		});
		const sessionRPRegistryModule = defineModule({
			name: "test:session-rp-registry",
			provides: { sessionRPRegistry: () => sessionRPRegistry },
		});
		const sessionFamilyIndexModule = defineModule({
			name: "test:session-family-index",
			provides: { sessionFamilyIndex: () => sessionFamilyIndex },
		});
		const sessionFederationIndexModule = defineModule({
			name: "test:session-federation-index",
			provides: { sessionFederationIndex: () => sessionFederationIndex },
		});
		const federationTokenStoreModule = defineModule({
			name: "test:federation-token-store",
			provides: { federationTokenStore: () => fedTokenStore },
		});
		const refreshTokenFamilyRevocationModule = defineModule({
			name: "test:refresh-token-family-revocation",
			provides: { refreshTokenFamilyRevocation: () => refreshTokenFamilyRevocation },
		});
		// federationProviders is SYNTHETIC: built from the "federations"
		// collector and injected by the boot planner as deps.federationProviders.
		// Every federations[name] contribution requires a paired
		// federationRedirectPolicies[name] contribution (a boot invariant).
		// `as never` at the contributes boundary admits the stub fixtures.
		const federationModule = defineModule({
			name: "test:google-federation",
			contributes: {
				federations: { google: () => googleProvider },
				federationRedirectPolicies: {
					google: () => ({
						validateRedirect: () => ({ ok: true as const, value: undefined }),
						resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
					}),
				},
			} as never,
		});
		const keyStoreWithSecret = defineModule({
			name: "test:key-store-logout",
			provides: { keyStore: () => createSymmetricKeyStore(SECRET) },
		});

		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" },
			},
		};

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				// Issuer is configured, so the discovery presence contract requires
				// the JWKS-owning module to be co-installed (it contributes jwks_uri).
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreWithSecret,
				userSessionStoreModule,
				sessionRPRegistryModule,
				sessionFamilyIndexModule,
				sessionFederationIndexModule,
				federationTokenStoreModule,
				refreshTokenFamilyRevocationModule,
				federationModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});

		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		const res = await request(app)
			.post("/oauth/federation/google/logout")
			.type("form")
			.set("Authorization", `Bearer ${accessToken}`)
			.send({});

		// The typed deps resolved the provider → endSession redirect
		expect(res.status).toBe(303);
		expect(res.headers.location).toContain("accounts.google.com");
		expect(googleProvider.endSession).toHaveBeenCalledOnce();

		await handle.dispose();
	});

	it("federation-token endpoint is mounted from the store wiring alone (returns 401, not 404)", async () => {
		// federationTokenSupported in routes.mts gates on the 4-store split +
		// federationTokenStore + refreshTokenFamilyRevocation, and on nothing
		// else: the endpoint forwards upstream and never mints our own `iss`.
		const sessionStore: UserSessionStore = {
			kind: "memory",
			create: vi.fn(),
			get: vi.fn(),
			delete: vi.fn(),
		};
		const sessionRPRegistry: SessionRPRegistry = {
			kind: "memory",
			registerRP: vi.fn(async () => {}),
			listRPs: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFamilyIndex: SessionFamilyIndex = {
			kind: "memory",
			addFamilyId: vi.fn(async () => {}),
			listFamilyIds: vi.fn(async () => []),
			removeBySid: vi.fn(async () => {}),
		};
		const sessionFederationIndex: SessionFederationIndex = {
			kind: "memory",
			addFederation: vi.fn(async () => {}),
			listFederations: vi.fn(async () => []),
			removeFederation: vi.fn(async () => {}),
			removeBySid: vi.fn(async () => {}),
		};
		const fedTokenStore: FederationTokenStore = {
			kind: "memory",
			attach: vi.fn(),
			get: vi.fn(),
			update: vi.fn(),
			removeBySid: vi.fn(),
			delete: vi.fn(),
		};
		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			isFamilyRevoked: vi.fn(async () => false),
			revokeFamily: vi.fn(),
		};

		const userSessionStoreModule = defineModule({
			name: "test:user-session-store-noissuer",
			provides: { userSessionStore: () => sessionStore },
		});
		const sessionRPRegistryModule = defineModule({
			name: "test:session-rp-registry-noissuer",
			provides: { sessionRPRegistry: () => sessionRPRegistry },
		});
		const sessionFamilyIndexModule = defineModule({
			name: "test:session-family-index-noissuer",
			provides: { sessionFamilyIndex: () => sessionFamilyIndex },
		});
		const sessionFederationIndexModule = defineModule({
			name: "test:session-federation-index-noissuer",
			provides: { sessionFederationIndex: () => sessionFederationIndex },
		});
		const federationTokenStoreModule = defineModule({
			name: "test:federation-token-store-noissuer",
			provides: { federationTokenStore: () => fedTokenStore },
		});
		const refreshTokenFamilyRevocationModule = defineModule({
			name: "test:refresh-token-family-revocation-noissuer",
			provides: { refreshTokenFamilyRevocation: () => refreshTokenFamilyRevocation },
		});

		const config = makeValidAppConfig();

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
				userSessionStoreModule,
				sessionRPRegistryModule,
				sessionFamilyIndexModule,
				sessionFederationIndexModule,
				federationTokenStoreModule,
				refreshTokenFamilyRevocationModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});

		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		// No Authorization header → should get 401 (route is mounted) not 404 (route missing)
		const res = await request(app).post("/oauth/federation/google/token").send({});
		expect(res.status).toBe(401);

		await handle.dispose();
	});
});

describe("absence policies", () => {
	it("carries the shared policy constants, by identity", async () => {
		// Identity, not shape: the declared-absence guard refuses modules whose
		// policies for one key disagree, and sharing the one constant is what
		// makes disagreement impossible by construction.
		const { ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY, AUDIT_SINK_ABSENCE_POLICY } = await import(
			"@o3co/auth-provider-core"
		);
		const manifest = oauthModule({ config: makeValidAppConfig() as never });
		expect(manifest.absencePolicies?.auditSink).toBe(AUDIT_SINK_ABSENCE_POLICY);
		expect(manifest.absencePolicies?.accessTokenDenylist).toBe(
			ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY,
		);
	});
});

describe("oauthModule — the login trip is the loginEntry slot when a module provides it", () => {
	const CLIENT = "client1";
	const REDIRECT = "https://rp.example/cb";
	const clientsWithOne = defineModule({
		name: "test:client-repository-with-one",
		provides: {
			clientRepository: (): ClientRepository => ({
				findById: async (id) =>
					id === CLIENT
						? ({
								clientId: CLIENT,
								tokenEndpointAuthMethod: "client_secret_basic",
								allowedRedirectUris: [REDIRECT],
								allowedScopes: ["read"],
								defaultScopes: ["read"],
								firstParty: true,
							} as never)
						: null,
				authenticate: async () => null,
			}),
		},
	});

	it("takes loginEntry as an optional slot: a composition without the session module boots", () => {
		const module = oauthModule({ config: makeValidAppConfig() as never });
		expect(module.optional).toContain("loginEntry");
		expect(module.requires).not.toContain("loginEntry");
	});

	const loginTrip = async (modules: readonly Module[]): Promise<string> => {
		const config = makeValidAppConfig();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientsWithOne,
				codeRepositoryModule,
				authorizationCodeGrantModule,
				keyStoreModule,
				...modules,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
		try {
			const app = express();
			app.use(handle.router);
			const res = await request(app)
				.get("/oauth/authorize")
				.query({ client_id: CLIENT, redirect_uri: REDIRECT, response_type: "code" });
			expect(res.status).toBe(302);
			return res.headers.location as string;
		} finally {
			await handle.dispose();
		}
	};

	it("sends a browser that is not signed in through the entry a module provides", async () => {
		const asked: string[] = [];
		const location = await loginTrip([
			defineModule({
				name: "test:login-entry",
				provides: {
					loginEntry: () =>
						Object.freeze({
							url: "/sign-in",
							urlFor: (returnTo: string) => {
								asked.push(returnTo);
								return `/sign-in?back=${encodeURIComponent(returnTo)}`;
							},
						}),
				},
			}),
		]);
		expect(asked).toHaveLength(1);
		expect(location).toBe(`/sign-in?back=${encodeURIComponent(asked[0] as string)}`);
	});

	it("reads endpoints.login.url when no module provides one", async () => {
		const location = await loginTrip([]);
		expect(location.startsWith("/login?redirect_to=")).toBe(true);
	});
});

describe("oauthModule — a consumer of session admission", () => {
	it("requires sessionRequirementResolver, the synthetic key every consumer of admission takes", () => {
		const module = oauthModule({ config: makeValidAppConfig() as never });
		expect(module.requires).toContain("sessionRequirementResolver");
		expect(module.requires).toContain("grantHandlerResolver");
	});

	it("registers the actions its routes admit, /authorize's and the consent step's, graded use", () => {
		const module = oauthModule({ config: makeValidAppConfig() as never });
		expect(module.contributes?.admissionActions).toEqual({
			"oauth.authorize": { grade: "use" },
			"oauth.consent": { grade: "use" },
		});
	});

	it("exports what createOAuthRouter admits, for a composition that mounts the router itself", async () => {
		const { OAUTH_ROUTER_ADMISSION_ACTIONS } = await import("#/index.mjs");
		expect(OAUTH_ROUTER_ADMISSION_ACTIONS).toEqual({
			"oauth.authorize": { grade: "use" },
			"oauth.consent": { grade: "use" },
		});
	});

	/** The configuration with the three session-bound grants switched as given. */
	const grantsConfig = (enabled: {
		readonly authorization_code: boolean;
		readonly refresh_token: boolean;
		readonly session: boolean;
	}) => {
		return withGrants(makeValidAppConfig(), {
			authorizationCode: enabled.authorization_code,
			refreshToken: enabled.refresh_token,
			session: enabled.session,
		}) as ReturnType<typeof makeValidAppConfig>;
	};

	it("registers each session-bound grant's action beside the grant, graded use", () => {
		const config = grantsConfig({ authorization_code: true, refresh_token: true, session: true });
		expect(oauthAuthorizationModule({ config }).contributes?.admissionActions).toEqual({
			"oauth.code_exchange": { grade: "use" },
			"oauth.refresh": { grade: "use" },
		});
		expect(oauthSessionModule({ config }).contributes?.admissionActions).toEqual({
			"oauth.session_grant": { grade: "use" },
		});
	});

	it("registers no grant's action while the grant is off: nothing admits it", () => {
		const config = grantsConfig({ authorization_code: true, refresh_token: false, session: false });
		expect(oauthAuthorizationModule({ config }).contributes?.admissionActions).toEqual({
			"oauth.code_exchange": { grade: "use" },
		});
		expect(oauthSessionModule({ config }).contributes?.admissionActions).toBeUndefined();
	});
});

describe("oauthModule — a composition with no authorization_code grant", () => {
	/**
	 * Tokens for machines only: client_credentials, no code repository, no
	 * session package. The issuer is set, so core serves the discovery
	 * document.
	 */
	const headlessConfig = (authorizationCode: boolean) => {
		const base = makeValidAppConfig();
		return withGrants(
			{
				...base,
				oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" } },
			},
			{ authorizationCode, refreshToken: false, clientCredentials: true },
		) as ReturnType<typeof makeValidAppConfig>;
	};
	const boot = (authorizationCode: boolean, extra: readonly Module[] = []) => {
		const config = headlessConfig(authorizationCode);
		return createTestApp({
			modules: [
				oauthModule({ config }),
				oauthAuthorizationModule({ config }),
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				keyStoreModule,
				...extra,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});
	};

	it("boots with no code repository, and answers /oauth/authorize 404 on GET and POST", async () => {
		const handle = await boot(false);
		const app = express();
		app.use(handle.router);

		expect((await request(app).get("/oauth/authorize")).status).toBe(404);
		expect((await request(app).post("/oauth/authorize")).status).toBe(404);
		await handle.dispose();
	});

	it.each(["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"])(
		"serves %s naming no authorization endpoint and no response type",
		async (path) => {
			const handle = await boot(false);
			const app = express();
			app.use(handle.router);

			const { status, body } = await request(app).get(path);
			expect(status).toBe(200);
			expect(body).not.toHaveProperty("authorization_endpoint");
			expect(body.response_types_supported).toEqual([]);
			expect(body.grant_types_supported).toEqual(["client_credentials"]);
			expect(body.token_endpoint).toBe("https://auth.example.com/oauth/token");
			expect(body).not.toHaveProperty("code_challenge_methods_supported");
			expect(body).not.toHaveProperty("request_uri_parameter_supported");
			await handle.dispose();
		},
	);

	it("with an acr table configured, advertises none and says nothing of it at boot", async () => {
		const base = headlessConfig(false);
		const config = {
			...base,
			oauth: {
				...base.oauth,
				authorize: { acrValues: { "urn:example:pwd": ["pwd"], "urn:example:mfa": ["pwd", "mfa"] } },
			},
		} as ReturnType<typeof makeValidAppConfig>;
		const logger = createMockLogger();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				oauthAuthorizationModule({ config }),
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s, logger },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		await handle.dispose();

		expect(body).not.toHaveProperty("acr_values_supported");
		const acrLines = [logger.info, logger.warn].flatMap((level) =>
			level.mock.calls.filter((call) => call[1] === "acr_value_unsatisfiable"),
		);
		expect(acrLines).toEqual([]);
	});

	it("refuses to boot a grant registered with no code repository, from the router", async () => {
		const config = headlessConfig(false);
		const refusal = await createTestApp({
			modules: [
				oauthModule({ config }),
				authorizationCodeGrantModule,
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(err: unknown) => err as { reason?: unknown; cause?: { message?: unknown } },
		);
		expect(refusal, "boot must be refused").toMatchObject({
			name: "BootError",
			reason: "contribute-factory-failed",
		});
		expect(String(refusal?.cause?.message)).toMatch(
			/authorization_code grant is registered but no codeRepository is wired/,
		);
	});

	it("with the grant and a code repository, serves /oauth/authorize and names it", async () => {
		const handle = await boot(true, [codeRepositoryModule]);
		const app = express();
		app.use(handle.router);

		expect((await request(app).get("/oauth/authorize")).status).not.toBe(404);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		expect(body.authorization_endpoint).toBe("https://auth.example.com/oauth/authorize");
		expect(body.response_types_supported).toEqual(["code"]);
		await handle.dispose();
	});
});
