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
 * Every module this template can turn on, booted together on one replica
 * through the real composition — the shipped HOCON, `buildModules`, core's
 * `createApp`, mounted as `app.mts` mounts it — and held to the contracts that
 * exist only when the modules meet: one discovery document that tells the
 * truth about every grant and endpoint, every module's route answering in the
 * same app, each module's body rules surviving its neighbours in either mount
 * order, and a store outage answered 503 and logged once.
 *
 * Each package's own suite boots that package alone or against stand-ins, and
 * the defects this file exists for were invisible there: a discovery document
 * made invalid by a neighbour's contribution, a disabled grant still
 * advertised, one module's prefix parser setting another's body limit, a
 * content-type rule that held in one mount order only. See
 * `all-modules-composition.fixture.mts` for what is real and what is
 * substituted, and `all-modules-composition.multi.test.mts` for the same
 * composition on Redis under `deployment.mode = "multi"`.
 *
 * `knownDefect` marks a contract the composition breaks today; its comment
 * names the defect. In the monorepo it is `it.fails`: the fix that mends the
 * defect turns the case red, and turns it into a plain `it`. An outage case
 * pins only the part of the #685 rule that is broken, and asserts the rest
 * (`describeOutages` in the fixture).
 */

import { readdirSync, readFileSync } from "node:fs";
import type { AppConfig } from "@o3co/auth-provider-core";
import type express from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
	ALICE,
	AS_LISTED,
	authorize,
	basic,
	type Composition,
	codeFrom,
	compose,
	contributionNames,
	cookiesOf,
	DISCOVERY_PATHS,
	describeOutages,
	expectValidMetadata,
	FEDERATION_LANDING,
	FORM_TYPE,
	federatedCallback,
	ISSUER,
	inMonorepo,
	JSON_TYPE,
	KIB,
	knownDefect,
	lodgeGrant,
	login,
	M2M,
	type ModuleOrder,
	type Outage,
	type OutageCase,
	padForm,
	padJson,
	REVERSED,
	redeem,
	SINGLE_ENV,
	TEMPLATE_DEPENDENCIES,
	THIRD,
	TOO_LARGE,
	TRANSFERS,
	WEB,
	WORKER,
	webTokens,
	withLength,
	withoutTheLine,
} from "./all-modules-composition.fixture.mjs";

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots and remembers the composition, so `afterEach` disposes it. */
async function boot(options: Parameters<typeof compose>[0] = {}): Promise<Composition> {
	current = await compose(options);
	return current;
}

// ---------------------------------------------------------------------------
// What is composed
// ---------------------------------------------------------------------------

/**
 * Every `@o3co/auth-provider-*` package the template depends on, and what the
 * all-on composition takes from it. A dependency added to `package.json`
 * without a line here fails the first case below, so a new module cannot be
 * shipped in the template without being booted here beside the rest.
 */
const TEMPLATE_PACKAGES: Readonly<Record<string, string>> = {
	"@o3co/auth-provider-core":
		"jwksModule, the memory stores, the refresh-token family rotation and revocation",
	"@o3co/auth-provider-federation-google": "googleFederationModule",
	"@o3co/auth-provider-federation-grants": "federationGrantsModules",
	"@o3co/auth-provider-federation-oidc": "oidcFederationModule, one per `oidc` section",
	"@o3co/auth-provider-foundation": "the HTTP user repository adapter (no module)",
	"@o3co/auth-provider-oauth":
		"oauthModule, oauthSessionModule, oauthAuthorizationModule, subjectRevocationServiceModule",
	"@o3co/auth-provider-redis": "the Redis stores (all-modules-composition.multi.test.mts)",
	"@o3co/auth-provider-session": "sessionModule, sessionStoreModuleFor",
};

/**
 * Workspace packages the template does not depend on, so nothing here can
 * boot them. Each is a module a deployment adds to this manifest by hand —
 * `modules.mts` provides the Redis clients their stores need for that reason
 * — and `tools/composition` in the monorepo boots each beside every module
 * here, through this file's fixture.
 */
const NOT_IN_TEMPLATE: Readonly<Record<string, string>> = {
	"@o3co/auth-provider-device-grant": "deviceGrantModule",
	"@o3co/auth-provider-dpop": "dpopModule",
	"@o3co/auth-provider-federation-apple": "appleFederationModule",
	"@o3co/auth-provider-federation-github": "githubFederationModule",
	"@o3co/auth-provider-mtls": "mtlsModule",
	"@o3co/auth-provider-oauth-token-exchange": "tokenExchangeModule",
	"@o3co/auth-provider-webauthn": "webauthnModule",
};

describe("what the all-modules composition covers", () => {
	it("names every @o3co/auth-provider-* package the template depends on", () => {
		const siblings = [...TEMPLATE_DEPENDENCIES].sort();
		expect(siblings).toEqual(Object.keys(TEMPLATE_PACKAGES).sort());
	});

	describe.runIf(inMonorepo)("in the monorepo", () => {
		it("places every workspace package: composed here, or listed as not in the template", () => {
			const packagesDir = new URL("../../../../packages/", import.meta.url);
			const workspace = readdirSync(packagesDir, { withFileTypes: true })
				.filter((entry) => entry.isDirectory())
				.map(
					(entry) =>
						(
							JSON.parse(
								readFileSync(new URL(`${entry.name}/package.json`, packagesDir), "utf8"),
							) as { name: string }
						).name,
				)
				.sort();
			expect(workspace.length).toBeGreaterThan(0);
			expect(workspace).toEqual(
				[...Object.keys(TEMPLATE_PACKAGES), ...Object.keys(NOT_IN_TEMPLATE)].sort(),
			);
		});
	});
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

/** What `buildModules` lists with every switch on, one replica, memory stores. */
const ALL_ON_MODULES = [
	"sessionStoreModule",
	"federation-grant-background",
	"federation-grants",
	"oauth",
	"oauth-session",
	"oauth-authorization",
	"jwks",
	"session",
	"federation:google",
	"standalone:google-federation-config",
	"standalone:oidc-federation-config",
	"federation:oidc:oidc",
	"standalone:key-store",
	"test:repositories",
	"standalone:audit-sink",
	"standalone:in-memory-federation-token-store",
	"core-federation-grant-store-memory",
	"core-federation-grant-intent-store-memory",
	"standalone:in-memory-session-stores",
	"core-rate-limiter-memory",
	"standalone:in-memory-code-repository",
	"core-access-token-denylist-memory",
	"core-replay-seen-set-memory",
	"core-consent-store-memory",
	"core-refresh-token-family-store-memory",
	"core-default-refresh-token-family-rotation",
	"core-default-refresh-token-family-revocation",
	"subject-revocation-service",
];

const ENABLED_GRANTS = ["authorization_code", "client_credentials", "refresh_token", "session"];

describe("every module the template can turn on boots together", () => {
	it("lists every module, and boots with nothing refused", async () => {
		const { modules } = await boot();
		expect(modules.map((m) => m.name)).toEqual(ALL_ON_MODULES);
	});

	it("mounts every route a module contributes", async () => {
		const { modules, handle } = await boot();
		const contributing = modules.filter((m) => contributionNames(m, "routes").length > 0);
		expect(contributing.length).toBeGreaterThan(0);
		const mountedBy = new Set(handle.routes.map((r) => r.contributedBy));
		for (const module of contributing) expect(mountedBy, module.name).toContain(module.name);
		expect(handle.routes.map((r) => r.contribution.id).sort()).toEqual(
			[
				"core:oidc-discovery",
				"federation-grants",
				"federation-grants-browser",
				"federation-routes",
				"jwks",
				"oauth-endpoints",
				"session-middleware",
				"session-routes",
			].sort(),
		);
	});

	it("registers every federation and every grant a module contributes", async () => {
		const { modules, handle, app } = await boot();
		const federations = modules.flatMap((m) => contributionNames(m, "federations")).sort();
		expect(federations).toEqual(["google", "oidc"]);
		expect([...(handle.components.federationProviders?.keys() ?? [])].sort()).toEqual(federations);

		const grants = modules.flatMap((m) => contributionNames(m, "grants")).sort();
		expect(grants).toEqual(ENABLED_GRANTS);
		const discovery = await request(app).get("/.well-known/openid-configuration");
		expect([...discovery.body.grant_types_supported].sort()).toEqual(grants);
	});

	it("hands the deployment's logger to every module that answers a request", async () => {
		// `app.mts` fills the `logger` slot so that `LOG_LEVEL` and the JSON
		// envelope reach every module; boot hands a module only the slots its
		// manifest names, so a route or grant module without `logger` writes
		// its outage lines to nobody (the session grant did, answering 503).
		const { modules } = await boot();
		const answering = modules.filter(
			(m) => contributionNames(m, "routes").length + contributionNames(m, "grants").length > 0,
		);
		expect(answering.length).toBeGreaterThan(5);
		for (const module of answering) {
			expect([...(module.requires ?? []), ...(module.optional ?? [])], module.name).toContain(
				"logger",
			);
		}
	});

	it("materializes every slot a module provides and another reads", async () => {
		// A provider boot dropped would leave its readers on their absence
		// branch; an unread one is never activated, so only read slots count.
		const { modules, handle } = await boot();
		const read = new Set(modules.flatMap((m) => [...(m.requires ?? []), ...(m.optional ?? [])]));
		const provided = modules.flatMap((m) => Object.keys(m.provides ?? {}));
		const expected = provided.filter((slot) => read.has(slot as never));
		expect(expected.length).toBeGreaterThan(10);
		const components = handle.components as Record<string, unknown>;
		for (const slot of expected) expect(components[slot], slot).toBeDefined();
	});
});

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

describe("discovery", () => {
	it.each(DISCOVERY_PATHS)("%s is valid and advertises every enabled grant", async (path) => {
		const { app } = await boot();
		const res = await request(app).get(path);
		expect(res.status).toBe(200);
		expectValidMetadata(res.body);
		expect([...res.body.grant_types_supported].sort()).toEqual(ENABLED_GRANTS);
		expect(res.body.client_id_metadata_document_supported).toBe(true);
		for (const endpoint of [
			"userinfo_endpoint",
			"introspection_endpoint",
			"revocation_endpoint",
			"end_session_endpoint",
		]) {
			expect(res.body[endpoint], endpoint).toBeDefined();
		}
	});

	it("serves the same document at both well-known paths", async () => {
		const { app } = await boot();
		const [oidc, oauth] = await Promise.all(DISCOVERY_PATHS.map((p) => request(app).get(p)));
		expect(oauth.body).toEqual(oidc.body);
	});

	it("advertises only endpoints the composed app answers", async () => {
		const { app } = await boot();
		const doc = (await request(app).get(DISCOVERY_PATHS[0])).body as Record<string, string>;
		const advertised = Object.entries(doc).filter(
			([field]) => field.endsWith("_endpoint") || field === "jwks_uri",
		);
		expect(advertised.length).toBeGreaterThanOrEqual(7);
		for (const [field, url] of advertised) {
			const { pathname } = new URL(url);
			const get = await request(app).get(pathname);
			const post = await request(app).post(pathname).type("form").send({});
			// The module's own answer (a refusal is fine), never express's 404.
			expect(
				[get.status, post.status].some((status) => status !== 404),
				field,
			).toBe(true);
		}
	});

	/**
	 * Each switch the template exposes, turned off alone: what it contributed
	 * is gone from the document and from the app, and nothing else moves.
	 */
	const GRANT_SWITCHES: ReadonlyArray<readonly [grant: string, variable: string]> = [
		["session", "OAUTH_GRANTS_SESSION_ENABLED"],
		["authorization_code", "OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED"],
		["refresh_token", "OAUTH_GRANTS_REFRESH_TOKEN_ENABLED"],
		["client_credentials", "OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED"],
	];

	it.each(GRANT_SWITCHES)(
		"%s off: absent from grant_types_supported and refused at the token endpoint",
		async (grant, variable) => {
			const { app } = await boot({ env: { ...SINGLE_ENV, [variable]: "false" } });
			const doc = (await request(app).get(DISCOVERY_PATHS[0])).body;
			expectValidMetadata(doc);
			expect([...doc.grant_types_supported].sort()).toEqual(
				ENABLED_GRANTS.filter((g) => g !== grant),
			);
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", basic(M2M))
				.type("form")
				.send({ grant_type: grant });
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("unsupported_grant_type");
		},
	);

	it("Client ID Metadata Documents off: the flag is gone and nothing else moves", async () => {
		const { app } = await boot({ env: { ...SINGLE_ENV, OAUTH_CIMD_ENABLED: "false" } });
		const doc = (await request(app).get(DISCOVERY_PATHS[0])).body;
		expectValidMetadata(doc);
		expect(doc.client_id_metadata_document_supported).toBeUndefined();
		expect([...doc.grant_types_supported].sort()).toEqual(ENABLED_GRANTS);
	});

	it("no consent store: the flag is gone (it could not be completed) and /oauth/consent is not mounted", async () => {
		// On, the consent route answers for itself: no session, `401 login_required`.
		const on = await boot();
		const mounted = await request(on.app).get("/oauth/consent");
		expect(mounted.status).toBe(401);
		expect(mounted.body.error).toBe("login_required");
		await on.handle.dispose();
		current = undefined;

		const { app } = await boot({ env: { ...SINGLE_ENV, CONSENT_STORE_ADAPTER: "none" } });
		const doc = (await request(app).get(DISCOVERY_PATHS[0])).body;
		expectValidMetadata(doc);
		expect(doc.client_id_metadata_document_supported).toBeUndefined();
		expect((await request(app).get("/oauth/consent")).status).toBe(404);
	});

	/** The grant connections dropped: they name the OIDC federation. */
	const withoutConnections = (config: AppConfig): AppConfig =>
		({ ...config, federationGrants: { ...config.federationGrants, connections: {} } }) as AppConfig;

	const FEATURE_SWITCHES: ReadonlyArray<
		readonly [
			feature: string,
			variable: string,
			path: string,
			config: ((config: AppConfig) => AppConfig) | undefined,
		]
	> = [
		["federation grants", "FEDERATION_GRANTS_ENABLED", "/oauth/federation-grants", undefined],
		[
			"the Google federation",
			"FEDERATIONS_GOOGLE_ENABLED",
			"/session/oauth/federation/google",
			undefined,
		],
		[
			"the OIDC federation",
			"FEDERATIONS_OIDC_ENABLED",
			"/session/oauth/federation/oidc",
			withoutConnections,
		],
	];

	it.each(FEATURE_SWITCHES)(
		"%s off: its route answers 404 and the document does not change",
		async (_feature, variable, path, config) => {
			const on = await boot(config ? { config } : {});
			const before = (await request(on.app).get(DISCOVERY_PATHS[0])).body;
			await on.handle.dispose();
			current = undefined;

			const { app } = await boot({ env: { ...SINGLE_ENV, [variable]: "false" }, config });
			const after = (await request(app).get(DISCOVERY_PATHS[0])).body;
			expect(after).toEqual(before);
			const res = path.startsWith("/oauth/")
				? await request(app).post(path).set("Authorization", basic(WORKER)).send({})
				: await request(app).get(path);
			expect(res.status).toBe(404);
		},
	);

	it("the OIDC federation off while a grant connection names it is refused at boot, naming both", async () => {
		await expect(
			compose({ env: { ...SINGLE_ENV, FEDERATIONS_OIDC_ENABLED: "false" } }),
		).rejects.toSatisfy((err: unknown) => {
			const e = err as { name?: string; cause?: { message?: string } };
			return (
				e.name === "BootError" &&
				/connections\.calendar: federation "oidc" is configured but disabled/.test(
					e.cause?.message ?? "",
				)
			);
		});
	});
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

describe("every module's primary route answers in the one app", () => {
	it("authorization code with PKCE, end to end, then refresh", async () => {
		const { app } = await boot();
		const { res: loggedIn, cookies } = await login(app);
		expect(loggedIn.status).toBe(200);
		const authorized = await authorize(app, cookies);
		expect(authorized.status).toBe(302);
		expect(authorized.headers.location).toMatch(new RegExp(`^${WEB.redirectUri}\\?code=`));
		const tokens = await redeem(app, codeFrom(authorized));
		expect(tokens.status).toBe(200);
		expect(tokens.body).toMatchObject({ token_type: "Bearer" });
		for (const field of ["access_token", "id_token", "refresh_token"]) {
			expect(typeof tokens.body[field], field).toBe("string");
		}

		const refreshed = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(WEB))
			.type("form")
			.send({ grant_type: "refresh_token", refresh_token: tokens.body.refresh_token });
		expect(refreshed.status).toBe(200);
		expect(refreshed.body.refresh_token).not.toBe(tokens.body.refresh_token);
	});

	it("client_credentials", async () => {
		const { app } = await boot();
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(M2M))
			.type("form")
			.send({ grant_type: "client_credentials", scope: "api.read" });
		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ token_type: "Bearer", scope: "api.read" });
	});

	it("the session grant, from the browser session", async () => {
		const { app } = await boot();
		const { cookies } = await login(app);
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(WEB))
			.set("Cookie", cookies)
			.type("form")
			.send({ grant_type: "session", scope: "openid" });
		expect(res.status).toBe(200);
		expect(typeof res.body.access_token).toBe("string");
	});

	it("introspection, userinfo and revocation of one access token", async () => {
		const { app } = await boot();
		const { access_token } = await webTokens(app);
		const introspect = () =>
			request(app)
				.post("/oauth/introspect")
				.set("Authorization", basic(WEB))
				.type("form")
				.send({ token: access_token });

		const active = await introspect();
		expect(active.status).toBe(200);
		expect(active.body).toMatchObject({ active: true, sub: ALICE.sub, client_id: WEB.id });

		const userinfo = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${access_token}`);
		expect(userinfo.status).toBe(200);
		expect(userinfo.body.sub).toBe(ALICE.sub);

		const revoked = await request(app)
			.post("/oauth/revoke")
			.set("Authorization", basic(WEB))
			.type("form")
			.send({ token: access_token });
		expect(revoked.status).toBe(200);
		expect((await introspect()).body).toEqual({ active: false });
	});

	it("JWKS publishes the key the tokens are signed under", async () => {
		const { app } = await boot();
		const { access_token } = await webTokens(app);
		const header = JSON.parse(
			Buffer.from(access_token.split(".")[0] as string, "base64url").toString(),
		) as { kid: string; alg: string };
		const jwks = await request(app).get("/.well-known/jwks.json");
		expect(jwks.status).toBe(200);
		expect(jwks.body.keys).toEqual([
			expect.objectContaining({ kid: header.kid, alg: header.alg, use: "sig" }),
		]);
	});

	it("the consent step sends a client that is not first-party to the consent page", async () => {
		const { app } = await boot();
		const { cookies } = await login(app);
		const res = await authorize(app, cookies, THIRD);
		expect(res.status).toBe(302);
		expect(res.headers.location).toMatch(/^\/consent\?challenge=/);
	});

	it.each([
		["oidc", "the OIDC federation"],
		["google", "the Google federation"],
	] as const)(
		"a login through %s (%s) ends in a session /authorize accepts",
		async (name, _federation) => {
			const { app, upstreams } = await boot();
			const callback = await (await federatedCallback(app, name, upstreams[name]))();
			expect(callback.status).toBe(302);
			expect(callback.headers.location).toBe(FEDERATION_LANDING);
			const authorized = await authorize(app, cookiesOf(callback));
			expect(authorized.status).toBe(302);
			expect(authorized.headers.location).toMatch(/\?code=/);
		},
	);

	// KNOWN DEFECT (the template's federation config, with the session
	// package's redirect policy): a federation enabled the way the template
	// README documents — its `FEDERATIONS_OIDC_*` variables — boots, and every
	// login through it then ends at the callback in `500 misconfiguration`
	// "client URL not configured", after the user has signed in upstream.
	// `clientUrl` has no environment form (`application.conf` ships it
	// commented out) and nothing at boot asks for it. Either shape of fix
	// passes: boot refusing the federation by the missing key, or the login
	// completing.
	knownDefect(
		"a federation enabled from the documented variables alone either refuses to boot or completes a login",
		async () => {
			const withoutLanding = (config: AppConfig): AppConfig => {
				const federations = config.federations as Record<string, Record<string, unknown>>;
				const { clientUrl: _dropped, ...oidc } = federations.oidc ?? {};
				return { ...config, federations: { ...federations, oidc } } as unknown as AppConfig;
			};
			let composed: Composition;
			try {
				composed = await boot({ config: withoutLanding });
			} catch (err) {
				// A refusal: a BootError that names the key.
				const e = err as { name?: string; message?: string; cause?: { message?: string } };
				expect(e.name).toBe("BootError");
				expect(`${e.message ?? ""} ${e.cause?.message ?? ""}`).toMatch(/clientUrl/);
				return;
			}
			// Or a completed login: the callback lands the browser somewhere, and
			// the session it made is one /authorize accepts.
			const callback = await (
				await federatedCallback(composed.app, "oidc", composed.upstreams.oidc)
			)();
			expect(callback.status).toBe(302);
			const authorized = await authorize(composed.app, cookiesOf(callback));
			expect(authorized.status).toBe(302);
			expect(authorized.headers.location).toMatch(/\?code=/);
		},
	);

	it("a federation grant is lodged, beside oauthModule under /oauth", async () => {
		const { app } = await boot();
		const res = await lodgeGrant(app);
		expect(res.status).toBe(201);
		expect(res.body).toMatchObject({ status: "pending" });
		expect(res.body.connect_uri).toMatch(
			new RegExp(`^${ISSUER}/session/federation-grants/connect\\?request=`),
		);
	});
});

// ---------------------------------------------------------------------------
// Bodies and content types
// ---------------------------------------------------------------------------

describe.each([AS_LISTED, REVERSED] satisfies ModuleOrder[])(
	"bodies and content types, modules %s",
	(order) => {
		// One boot per order: nothing below changes what the next request meets.
		let composed: Composition;
		beforeAll(async () => {
			composed = await compose({ order });
		});
		afterAll(async () => {
			await composed.handle.dispose();
		});

		it("mounts in a different order from the other case, under /oauth and under /session", () => {
			const ids = composed.handle.routes.map((r) => r.contribution.id);
			for (const [neighbour, own] of [
				["federation-grants", "oauth-endpoints"],
				["federation-grants-browser", "session-routes"],
			] as const) {
				expect(ids, own).toContain(own);
				expect(ids, neighbour).toContain(neighbour);
				expect(ids.indexOf(neighbour) < ids.indexOf(own), `${neighbour} / ${own}`).toBe(
					order === AS_LISTED,
				);
			}
		});

		it.each(TRANSFERS)(
			"federation grants keep their 16 KiB bound beneath oauthModule's /oauth, a body sent %s",
			async (_transfer, send) => {
				for (const type of [JSON_TYPE, FORM_TYPE]) {
					const body =
						type === JSON_TYPE ? padJson(40 * KIB) : padForm(40 * KIB, "sub=local-subject");
					const res = await send(composed.app, "/oauth/federation-grants", type, body, {
						authorization: basic(WORKER),
					});
					expect(res.status, type).toBe(413);
					expect(res.body, type).toEqual({
						error: "invalid_request",
						error_description: "body_too_large",
					});
				}
			},
		);

		it.each(TRANSFERS)(
			"the grants consent route keeps its 16 KiB bound beneath sessionModule's /session, a body sent %s",
			async (_transfer, send) => {
				const res = await send(
					composed.app,
					"/session/federation-grants/consent",
					JSON_TYPE,
					padJson(40 * KIB),
				);
				expect(res.status).toBe(413);
				expect(res.body).toEqual({ error: "invalid_request", error_description: "body_too_large" });
			},
		);

		it.each(TRANSFERS)(
			"the token endpoint parses past a neighbour's 16 KiB and stops at its own 100 KiB, a body sent %s",
			async (_transfer, send) => {
				const headers = { authorization: basic(M2M) };
				const fields = "grant_type=client_credentials";
				const within = await send(
					composed.app,
					"/oauth/token",
					FORM_TYPE,
					padForm(50 * KIB, fields),
					headers,
				);
				// Parsed and handed to the grant, which refuses the missing scope.
				expect(within.status).toBe(400);
				expect(within.body.error).toBe("invalid_scope");
				const over = await send(
					composed.app,
					"/oauth/token",
					FORM_TYPE,
					padForm(150 * KIB, fields),
					headers,
				);
				expect(over.status).toBe(413);
				expect(over.body).toEqual(TOO_LARGE);
			},
		);

		it.each(TRANSFERS)(
			"the login route parses past a neighbour's 16 KiB and stops at its own 100 KiB, a body sent %s",
			async (_transfer, send) => {
				const fields = `username=${ALICE.username}&password=x`;
				const within = await send(
					composed.app,
					"/session/login",
					FORM_TYPE,
					padForm(50 * KIB, fields),
				);
				// Parsed and handed to the route, whose CSRF check refuses it.
				expect(within.status).toBe(403);
				expect(within.body.error).toBe("access_denied");
				const over = await send(
					composed.app,
					"/session/login",
					FORM_TYPE,
					padForm(150 * KIB, fields),
				);
				expect(over.status).toBe(413);
				expect(over.body).toEqual(TOO_LARGE);
			},
		);

		it("each module answers a body it cannot read with its own refusal", async () => {
			const { app } = composed;
			const grants = { authorization: basic(WORKER) };
			expect(
				await withLength(app, "/oauth/federation-grants", "text/plain", "hello", grants),
			).toEqual({
				status: 415,
				body: { error: "invalid_request", error_description: "unsupported_content_type" },
			});
			expect(await withLength(app, "/oauth/federation-grants", JSON_TYPE, "{nope", grants)).toEqual(
				{
					status: 400,
					body: { error: "invalid_request", error_description: "malformed_body" },
				},
			);
			expect(
				await withLength(app, "/session/federation-grants/consent", JSON_TYPE, "{nope"),
			).toEqual({
				status: 400,
				body: { error: "invalid_request", error_description: "malformed_body" },
			});
			const token = await withLength(app, "/oauth/token", JSON_TYPE, "{nope", {
				authorization: basic(M2M),
			});
			expect(token.status).toBe(400);
			expect(token.body.error).toBe("invalid_request");
		});
	},
);

describe("a request body the OAuth endpoints do not parse", () => {
	// KNOWN DEFECT (packages/oauth, `createOAuthRouter` in routes.mts): the
	// token and introspection handlers read `req.body` without checking that a
	// parser ran. A body that is neither a form nor JSON — or none at all —
	// leaves it undefined, the handler throws, and the terminal handler answers
	// `500 server_error` and logs `unhandled_request_error` for the client's
	// own mistake. `/oauth/revoke` checks, and answers 400.
	knownDefect.each([
		["/oauth/token", "text/plain"],
		["/oauth/token", "application/xml"],
		["/oauth/introspect", "text/plain"],
	])(
		"%s with %s is the client's mistake: 400 invalid_request, nothing logged",
		async (path, type) => {
			const { app, logger } = await boot();
			const res = await request(app)
				.post(path)
				.set("Authorization", basic(M2M))
				.set("Content-Type", type)
				.send("grant_type=client_credentials");
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_request");
			expect(logger.lines.filter((line) => line.level === "error")).toEqual([]);
		},
	);
});

// ---------------------------------------------------------------------------
// Outages
// ---------------------------------------------------------------------------

const tokenRequest = (app: express.Express, client: { id: string; secret: string }) =>
	request(app).post("/oauth/token").set("Authorization", basic(client)).type("form");

/** The code exchange, with the store taken down just before the redeem. */
const codeExchange = async (app: express.Express, outage: Outage) => {
	const { cookies } = await login(app);
	const code = codeFrom(await authorize(app, cookies));
	outage.down = true;
	return redeem(app, code);
};

/** The refresh grant, with the store taken down just before the refresh. */
const refresh = async (app: express.Express, outage: Outage) => {
	const { refresh_token } = await webTokens(app);
	outage.down = true;
	return tokenRequest(app, WEB).send({ grant_type: "refresh_token", refresh_token });
};

/** A login through the OIDC federation, with the store taken down just before the callback. */
const oidcCallback = async (app: express.Express, outage: Outage, c: Composition) => {
	const callback = await federatedCallback(app, "oidc", c.upstreams.oidc);
	outage.down = true;
	return callback();
};

const VERIFIER_WARN =
	"core's verifier (`verifyJwt`, `packages/core/src/jwt/verify.mts`) writes its own `jwt_verify_rejected` warn (`reason: \"revocation_unavailable\"`) beside the route's error line: two lines for one outage (the runbook's outage table documents both)";

const FEDERATION_GRANTS_WARN =
	'packages/federation-grants: the outage is answered 503 but logged at warn, as "federation grant operation failed" with a classification and no error projection';

const OUTAGES: readonly OutageCase[] = [
	{
		module: "oauth-authorization",
		slot: "codeRepository",
		surface: "the code exchange",
		run: codeExchange,
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "authorization_grant_store_unavailable",
	},
	{
		module: "oauth-authorization",
		slot: "sessionFamilyIndex",
		surface: "the code exchange",
		run: codeExchange,
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "authorization_grant_store_unavailable",
	},
	{
		module: "oauth-authorization",
		slot: "sessionRPRegistry",
		surface: "the code exchange",
		run: codeExchange,
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "authorization_grant_store_unavailable",
	},
	{
		module: "oauth",
		slot: "codeRepository",
		surface: "/oauth/authorize",
		run: async (app, outage) => {
			const { cookies } = await login(app);
			outage.down = true;
			return authorize(app, cookies);
		},
		answer: { redirect: WEB.redirectUri, error: "temporarily_unavailable" },
		event: "authorize_store_unavailable",
	},
	{
		module: "oauth-authorization",
		slot: "refreshTokenFamilyStore",
		surface: "the refresh grant",
		run: refresh,
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "refresh_token_store_unavailable",
		unrelatedWarns: ["jwt_verify_aud_skipped"],
	},
	{
		module: "oauth-authorization",
		slot: "subjectRevocation",
		surface: "the refresh grant",
		run: refresh,
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "token_verification_unavailable",
		unrelatedWarns: ["jwt_verify_aud_skipped"],
		defects: { "no-warn": VERIFIER_WARN },
	},
	{
		module: "oauth",
		slot: "accessTokenDenylist",
		surface: "/oauth/revoke",
		run: async (app, outage) => {
			const { access_token } = await webTokens(app);
			outage.down = true;
			return request(app)
				.post("/oauth/revoke")
				.set("Authorization", basic(WEB))
				.type("form")
				.send({ token: access_token });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "revoke_store_unavailable",
	},
	{
		module: "oauth",
		slot: "accessTokenDenylist",
		surface: "/oauth/introspect",
		run: async (app, outage) => {
			const { access_token } = await webTokens(app);
			outage.down = true;
			return request(app)
				.post("/oauth/introspect")
				.set("Authorization", basic(WEB))
				.type("form")
				.send({ token: access_token });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "token_verification_unavailable",
		defects: { "no-warn": VERIFIER_WARN },
	},
	{
		module: "oauth",
		slot: "userSessionStore",
		surface: "/oauth/userinfo",
		run: async (app, outage) => {
			const { access_token } = await webTokens(app);
			outage.down = true;
			return request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${access_token}`);
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "userinfo_store_unavailable",
		unrelatedWarns: ["jwt_verify_aud_skipped"],
	},
	{
		module: "oauth-session",
		slot: "userSessionStore",
		surface: "the session grant",
		run: async (app, outage) => {
			const { cookies } = await login(app);
			outage.down = true;
			return tokenRequest(app, WEB)
				.set("Cookie", cookies)
				.send({ grant_type: "session", scope: "openid" });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "session_grant_store_unavailable",
	},
	{
		module: "oauth (consent step)",
		slot: "consentStore",
		surface: "/oauth/authorize for a client that is not first-party",
		run: async (app, outage) => {
			const { cookies } = await login(app);
			outage.down = true;
			return authorize(app, cookies, THIRD);
		},
		answer: { redirect: THIRD.redirectUri, error: "temporarily_unavailable" },
		event: "authorize_consent_store_unavailable",
		defects: {
			"store-field":
				"packages/oauth `routes/authorize.mts`: `authorize_consent_store_unavailable` carries `clientId` and `err` but no `store` / `step` / `site` field",
		},
	},
	{
		module: "oauth (consent step)",
		slot: "pendingConsentStore",
		surface: "/oauth/authorize for a client that is not first-party",
		run: async (app, outage) => {
			const { cookies } = await login(app);
			outage.down = true;
			return authorize(app, cookies, THIRD);
		},
		answer: { redirect: THIRD.redirectUri, error: "temporarily_unavailable" },
		event: "authorize_pending_consent_store_unavailable",
		defects: {
			"store-field":
				"packages/oauth `routes/authorize.mts`: `authorize_pending_consent_store_unavailable` carries `clientId` and `err` but no `store` / `step` / `site` field",
		},
	},
	{
		module: "session",
		slot: "userSessionStore",
		surface: "/session/login",
		run: async (app, outage) => {
			outage.down = true;
			return (await login(app)).res;
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		defects: withoutTheLine(
			"packages/session `routes/Session.mts`: the login route's `userSessionStore.create` failure answers 503 from a bare `catch {}` and logs nothing — a silent 503",
		),
	},
	{
		module: "session",
		slot: "userRepository",
		surface: "/session/login",
		run: async (app, outage) => {
			outage.down = true;
			return (await login(app)).res;
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		defects: {
			...withoutTheLine(
				'packages/session `routes/Session.mts`: a user-repository failure at login is answered 503 "User directory temporarily unavailable" but logged only at warn, as "local login authenticate failed"',
			),
			"no-warn":
				'packages/session `routes/Session.mts`: the outage\'s only line is the warn "local login authenticate failed"',
		},
	},
	{
		module: "oauth (client authentication)",
		slot: "clientRepository",
		surface: "/oauth/token",
		run: async (app, outage) => {
			outage.down = true;
			return tokenRequest(app, M2M).send({ grant_type: "client_credentials", scope: "api.read" });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "client_repository_unavailable",
	},
	{
		module: "oauth",
		slot: "clientRepository",
		surface: "/oauth/authorize",
		run: async (app, outage) => {
			const { cookies } = await login(app);
			outage.down = true;
			return authorize(app, cookies);
		},
		// JSON, not a redirect: no redirect target is trusted before the client is known.
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "client_repository_unavailable",
	},
	{
		module: "session",
		slot: "subjectSessionIndex",
		surface: "/session/login",
		run: async (app, outage) => {
			outage.down = true;
			return (await login(app)).res;
		},
		// Intended (#296): the login is not denied for a best-effort index write,
		// and the missed write is logged at error because a token minted from
		// this session keeps introspecting active after a credential change —
		// the runbook pages on it.
		answer: { status: 200 },
		event: "subject_session_index_write_failed",
		storeFieldNotRequired:
			"the login succeeds; the line records a missed best-effort write, named by its event, with the subject and the session",
	},
	{
		module: "session",
		slot: "federationTokenStore",
		surface: "the OIDC federation callback",
		run: oidcCallback,
		answer: { status: 503, error: "temporarily_unavailable" },
		defects: {
			answer:
				'packages/session `routes/Federation.mts`: a federation-token-store failure at the callback is caught by the post-create catch and answered `500 session_create_failed` "Internal error: session could not be persisted"',
			"store-field":
				'packages/session `routes/Federation.mts`: the post-create catch logs "session post-create failed" at error with `provider`, `sid` and `err`, but no `store` / `step` / `site` field',
		},
	},
	{
		module: "session",
		slot: "sessionFederationIndex",
		surface: "the OIDC federation callback",
		run: oidcCallback,
		answer: { status: 503, error: "temporarily_unavailable" },
		defects: {
			...withoutTheLine(
				'packages/session `routes/Federation.mts`: a session-federation-index failure at the callback is answered 503 but logged only at warn, as "sessionFederationIndex.addFederation failed"',
			),
			"no-warn":
				'packages/session `routes/Federation.mts`: the outage\'s only line is the warn "sessionFederationIndex.addFederation failed"',
		},
	},
	{
		module: "core (rate-limit guard)",
		slot: "rateLimiter",
		surface: "/oauth/token (rateLimit.failMode = closed)",
		run: async (app, outage) => {
			outage.down = true;
			return tokenRequest(app, M2M).send({ grant_type: "client_credentials", scope: "api.read" });
		},
		answer: { status: 503, error: "service_unavailable" },
		event: "rate_limiter_failed_closed",
		defects: {
			"store-field":
				"core's rate-limit guard (`packages/core/src/ratelimit/guard.mts`): `rate_limiter_failed_closed` names the limiter by `tag`, not `store` / `step` / `site`",
			projection:
				"core's rate-limit guard (`packages/core/src/ratelimit/guard.mts`): the limiter's error is flattened to a string under `error` (the projection's `detail` or `name`), not the projection under `err`",
		},
	},
	{
		module: "federation-grants",
		slot: "federationGrantStore",
		surface: "POST /oauth/federation-grants/:grantId/status",
		run: async (app, outage) => {
			const lodged = await lodgeGrant(app);
			outage.down = true;
			return request(app)
				.post(`/oauth/federation-grants/${lodged.body.grant_id as string}/status`)
				.set("Authorization", basic(WORKER))
				.send({ sub: ALICE.sub });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		defects: { ...withoutTheLine(FEDERATION_GRANTS_WARN), "no-warn": FEDERATION_GRANTS_WARN },
	},
	{
		module: "federation-grants",
		slot: "federationGrantIntentStore",
		surface: "POST /oauth/federation-grants (lodging)",
		run: async (app, outage) => {
			outage.down = true;
			return lodgeGrant(app);
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		defects: { ...withoutTheLine(FEDERATION_GRANTS_WARN), "no-warn": FEDERATION_GRANTS_WARN },
	},
	{
		module: "jwks",
		slot: "keyStore",
		surface: "/.well-known/jwks.json",
		run: async (app, outage) => {
			outage.down = true;
			return request(app).get("/.well-known/jwks.json");
		},
		answer: { status: 503, error: "jwks_unavailable" },
		event: "jwks_unavailable",
		defects: {
			"store-field":
				"core's JWKS route (`packages/core/src/routes/Jwks.mts`): `jwks_unavailable` carries `algorithm` and `err` but no `store` / `step` / `site` field naming the key store",
		},
	},
];

describeOutages(
	"a store or repository outage answers 503 and is logged once, at error (#685)",
	OUTAGES,
	(outage) => compose({ outage }),
);
