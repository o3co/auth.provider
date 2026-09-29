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
import { createMockLogger } from "./_helpers/mockLogger.mjs";

/**
 * A federation that satisfies the contract, with whatever capability the case
 * under test adds. Since #626 P1 `federationProviders` carries
 * `FederationProvider` rather than a one-field stand-in, so a mock has to be
 * one — which is the point: these routes read a provider the boot planner
 * could actually have handed them.
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
	// D-1: Code requires client_id + redirect_uri.
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

// #282: the JWKS route refuses to publish an empty key set, so the
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
// Module manifest structural tests (§7.1 — static, no createTestApp needed)
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
		// The base schema marks endpoints.login.url optional, but oauthConfigSchema
		// must tighten it to z.string().min(1) so boot fails before /authorize is hit.
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

	it("includes only oauth-endpoints when issuer is absent (JWKS moved to core jwksModule)", () => {
		const base = makeValidAppConfig();
		// No issuer set — only oauth-endpoints is contributed. oidc-discovery is
		// issuer-gated; JWKS is no longer an oauth contribution (core jwksModule
		// owns it now).
		const module = oauthModule({ config: base });
		const routes = module.contributes?.routes;
		expect(Array.isArray(routes)).toBe(true);
		expect((routes as unknown[]).length).toBe(1);
	});

	it("contributes a single oauth-endpoints route regardless of issuer (discovery is core-aggregated)", () => {
		// Discovery is no longer an oauth ROUTE; oauth contributes a
		// `discoveryMetadata` slice instead, which core's assembleApp aggregates
		// into `/.well-known/openid-configuration`. So oauth always contributes
		// exactly one route (oauth-endpoints), issuer or not.
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
// createTestApp integration tests (§7.3 — boot + inspect)
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
					// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
					// denylist behind it. Memory is right here — one process, one test.
					memoryAccessTokenDenylistModule,
					clientRepositoryModule,
					codeRepositoryModule,
					keyStoreModule,
				],
				bootstrapComponents: { config, pathResolver: (s) => s },
			}),
		).rejects.toMatchObject({
			name: "BootError",
			reason: "config-validation-failed",
		} satisfies Partial<InstanceType<typeof BootError>>);
	});
});

describe("oauthModule — createTestApp route inspection", () => {
	it("contributes no oidc-discovery route even with an issuer; core mounts discovery from aggregated metadata", async () => {
		// Discovery is now mounted by core's assembleApp from the aggregated
		// `discoveryMetadata` collector — it is NOT an oauth route contribution,
		// so it never appears in the inspected route ids. jwksModule is co-installed
		// so the issuer-enabled composition forms a valid discovery document
		// (jwks owns `jwks_uri`); without it boot fails the presence contract.
		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, jwt: { ...base.oauth.jwt, issuer: "https://auth.example.com" } },
		};
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const routeIds = handle.inspect.routes.map((r) => r.contribution.id);
		expect(routeIds).toContain("oauth-endpoints");
		expect(routeIds).not.toContain("oidc-discovery");
		await handle.dispose();
	});

	it("oauth-endpoints is mounted at /oauth", async () => {
		const config = makeValidAppConfig();
		// jwksModule is co-installed because every config now carries an issuer
		// (#266), so the provider-root contribution always activates discovery —
		// which requires a module owning `jwks_uri` to form a valid document.
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const res = await request(app).get("/.well-known/openid-configuration");
		expect(res.status).toBe(200);
		expect(res.body.issuer).toBe("https://auth.example.com");
		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// Discovery <-> JWKS path agreement (presence + config-drift contract).
//
// JWKS is now contributed by the core `jwksModule`, while oidc-discovery
// (which advertises `jwks_uri`) is contributed by oauth. They live in
// different modules, so an issuer-enabled composition MUST co-install both
// or discovery publishes a dangling `jwks_uri`. These tests pin that
// cross-module contract end-to-end: the advertised `jwks_uri` must resolve
// to a mounted JWKS route, including under an `oauth.jwt.jwksPath` override
// (both endpoints resolve the path via the shared `resolveJwksPath`, so
// they cannot drift).
// ---------------------------------------------------------------------------

describe("oauthModule — the acr table in the served discovery document (the MFA ADR's D15)", () => {
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
				asymmetricKeyStoreModule,
				...extraModules,
			],
			bootstrapComponents: { config, pathResolver: (s) => s, logger },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		await handle.dispose();
		const lines = (level: ReturnType<typeof vi.fn>) =>
			level.mock.calls.filter((call) => call[1] === "acr_value_unsatisfiable");
		return { body, logger, lines };
	};

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

	it("drops what only an upstream IdP could assert while the installed federation does not trust its amr (the MFA ADR's D13)", async () => {
		// The default: an upstream `mfa` is kept apart from the session's `amr`
		// and meets no `acr`, so the entry is one nothing installed can meet.
		// The section as a composition that installs the module itself writes
		// it: `enabled` is the template's switch, and this composition has none
		// of the session stores an enabled federation needs.
		const { body, logger, lines } = await boot([googleFederationModule], { google: {} });
		expect(body.acr_values_supported).toEqual(["urn:example:pwd"]);
		expect(lines(logger.info)).toEqual([
			[{ acr: "urn:example:mfa", unproducible: ["mfa"] }, "acr_value_unsatisfiable"],
		]);
		expect(lines(logger.warn)).toEqual([]);
	});

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
		// A hand-built configuration: core's schema refuses it at boot too.
		await expect(
			boot([googleFederationModule], { google: { trustUpstreamAmr: "yes" } }),
		).rejects.toThrow("federations.google.trustUpstreamAmr must be true or false");
	});
});

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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				// Asymmetric: since #282 the JWKS route refuses to publish an
				// empty key set, so "resolves to a mounted route" is only
				// observable with a keystore that has public material.
				asymmetricKeyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
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
		// carries EXACTLY these fields. `toEqual` is the point — a field added by
		// a future contribution has to be argued for here rather than appearing in
		// the served document unnoticed.
		//
		// #283 changed this set: `grant_types_supported`, `revocation_endpoint` +
		// its auth methods, and `introspection_endpoint_auth_methods_supported`
		// are new. `grant_types_supported` is `[]` because this composition
		// registers no grant module at all — POST /oauth/token would answer
		// `unsupported_grant_type` for every value, and that is what the empty
		// array says. Omitting the field would instead have claimed
		// `authorization_code` + `implicit` (RFC 8414 §2's default).
		const config = issuerConfig();
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		const iss = "https://auth.example.com";
		expect(body).toEqual({
			issuer: iss,
			authorization_endpoint: `${iss}/oauth/authorize`,
			token_endpoint: `${iss}/oauth/token`,
			userinfo_endpoint: `${iss}/oauth/userinfo`,
			jwks_uri: `${iss}/.well-known/jwks.json`,
			introspection_endpoint: `${iss}/oauth/introspect`,
			// #283: /oauth/revoke is always mounted, and this composition wires the
			// memory denylist, so it can actually revoke something.
			revocation_endpoint: `${iss}/oauth/revoke`,
			response_types_supported: ["code"],
			// #284: emitted BECAUSE its OIDC Discovery default is `true` — an
			// omitted field here claimed support for `request_uri`, which
			// `/authorize` refuses. The sibling `*_parameter_supported` fields
			// default to `false` and stay absent.
			request_uri_parameter_supported: false,
			subject_types_supported: ["public"],
			// keyStoreModule signs HS256, so the aggregator advertises exactly that.
			id_token_signing_alg_values_supported: ["HS256"],
			scopes_supported: ["openid", "profile", "email", "groups"],
			grant_types_supported: [],
			// #484: private_key_jwt on every client-authenticated endpoint, with
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
			code_challenge_methods_supported: ["S256"],
		});
		await handle.dispose();
	});

	it('omits revocation_endpoint end-to-end under oauth.revocation.accessToken = "unsupported" with no other revocation capability', async () => {
		// The composition #277 made legal: declaring the access-token capability
		// absent is what lets a deployment boot with no `accessTokenDenylist`
		// (core's step 13.9 returns early on `"unsupported"`). With no
		// `refreshTokenFamilyRevocation` either, `POST /oauth/revoke` is mounted
		// and revokes nothing, so the served document must not name it.
		//
		// End-to-end rather than unit-only because the value of this case is that
		// the same config both survives the boot validator AND produces a document
		// without the endpoint — two layers reading the one #277 key the same way.
		const base = issuerConfig();
		const config = {
			...base,
			// `subject: "unsupported"` rides along because this override replaces
			// the whole `revocation` object, and the fixture's declaration
			// (#406) goes with it. This composition wires no subject stores
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
			bootstrapComponents: { config, pathResolver: (s) => s },
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

	it("advertises exactly the grant types the config actually enabled (#283)", async () => {
		// End-to-end guard on the anti-drift property: `grant_types_supported` is
		// read off the same `grantHandlerResolver` `/oauth/token` dispatches
		// against, so a grant gated off by `oauth.grants.<name>.enabled` cannot be
		// advertised, and one gated on cannot be missed.
		const base = issuerConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				grants: {
					...base.oauth.grants,
					authorization_code: { enabled: true },
					refresh_token: { enabled: true },
					// Left off on purpose — it must not appear below.
					client_credentials: { enabled: false },
				},
			},
		} as ReturnType<typeof makeValidAppConfig>;
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
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		expect(body.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
		expect(body.grant_types_supported).not.toContain("client_credentials");
		// RFC 8414 §2's omitted-default was `["authorization_code", "implicit"]`.
		// The field exists precisely so `implicit` stops being implied.
		expect(body.grant_types_supported).not.toContain("implicit");
		await handle.dispose();
	});

	it("honors oauth.jwt.jwksPath for BOTH the advertised jwks_uri and the mounted route", async () => {
		const config = issuerConfig({ jwksPath: "/keys/jwks.json" });
		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				asymmetricKeyStoreModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});
		const app = express();
		app.use(handle.router);
		const disco = await request(app).get("/.well-known/openid-configuration");
		expect(disco.body.jwks_uri).toBe("https://auth.example.com/keys/jwks.json");
		const jwksPath = new URL(disco.body.jwks_uri as string).pathname;
		expect((await request(app).get(jwksPath)).status).toBe(200);
		// The old default path is no longer served under the override.
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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreWithSecret,
				rateLimiterModule,
				auditSinkModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
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
// Proves that oauthModule reads federationProviders from typed deps (Theme E
// structural fix — no lazy () => ctx.federationProviders closure). Federation
// providers are supplied at boot time via the DI graph.
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
		// federationProviders is SYNTHETIC — built from the "federations" collector.
		// Contribute the google provider via a federation module; the boot planner
		// then injects it as deps.federationProviders in the route factory.
		// Theme E structural fix: no lazy () => ctx.federationProviders closure.
		//
		// Note: every federations[name] contribution requires a paired
		// federationRedirectPolicies[name] contribution (boot invariant §7.5).
		// Both FederationProvider and FederationRedirectPolicy are `unknown`
		// placeholders in contributes-map (Phase 9); `as never` at the contributes
		// boundary is the plan-sanctioned escape hatch for stub module fixtures.
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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
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
			bootstrapComponents: { config, pathResolver: (s) => s },
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
		// else — the endpoint forwards upstream and never mints our own `iss`.
		// It used to be worth asserting that an absent issuer did not break the
		// gate; since #266 an issuer is always configured, so what this pins is
		// that the gate is the store wiring.
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
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
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
			bootstrapComponents: { config, pathResolver: (s) => s },
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

describe("absence policies (#363, #375)", () => {
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

describe("oauthModule — the login trip is the loginEntry slot when a module provides it (#728)", () => {
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
				keyStoreModule,
				...modules,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
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

	it("reads endpoints.login.url, as before, when no module provides one", async () => {
		const location = await loginTrip([]);
		expect(location.startsWith("/login?redirect_to=")).toBe(true);
	});
});

describe("oauthModule — a consumer of session admission (the session-admission ADR's D1, D6)", () => {
	it("requires sessionRequirementResolver, the synthetic key every consumer of admission takes", () => {
		const module = oauthModule({ config: makeValidAppConfig() as never });
		expect(module.requires).toContain("sessionRequirementResolver");
		expect(module.requires).toContain("grantHandlerResolver");
	});
});
