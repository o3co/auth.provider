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
 * `it.fails` marks a contract the composition breaks today; its comment names
 * the defect. When the defect is fixed the case starts failing, and the fix
 * turns it into a plain `it`.
 */

import { readdirSync, readFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { AppConfig, Module } from "@o3co/auth-provider-core";
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
	cookiesOf,
	FEDERATION_LANDING,
	federatedCallback,
	ISSUER,
	type LogLine,
	lodgeGrant,
	login,
	M2M,
	type ModuleOrder,
	type Outage,
	REVERSED,
	redeem,
	SINGLE_ENV,
	THIRD,
	WEB,
	WORKER,
	webTokens,
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
 * `modules.mts` already provides the device-code store's Redis client for
 * that reason — and each is a `todo` below until a composition that depends
 * on it boots it beside the rest.
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

const templateManifest = JSON.parse(
	readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
) as { dependencies: Record<string, string> };

/**
 * Inside the monorepo the template names its siblings `workspace:*`; a
 * scaffold, and CI's packed-tarball run, name versions or tarballs. Only the
 * monorepo has a workspace for the package list to drift from.
 */
const inMonorepo =
	templateManifest.dependencies["@o3co/auth-provider-core"]?.startsWith("workspace:") === true;

describe("what the all-modules composition covers", () => {
	it("names every @o3co/auth-provider-* package the template depends on", () => {
		const siblings = Object.keys(templateManifest.dependencies)
			.filter((name) => name.startsWith("@o3co/auth-provider-"))
			.sort();
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

		for (const [name, module] of Object.entries(NOT_IN_TEMPLATE)) {
			it.todo(
				`boots ${module} (${name}) beside every other module — needs a composition that depends on ${name}`,
			);
		}
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

const contributionNames = (module: Module, kind: string): string[] => {
	const contribution = (module.contributes as Record<string, unknown> | undefined)?.[kind];
	if (contribution === undefined) return [];
	return Array.isArray(contribution) ? [module.name] : Object.keys(contribution as object);
};

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

const DISCOVERY_PATHS = [
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
];

/**
 * What RFC 8414 §2 and OpenID Connect Discovery §3 require of the document
 * this composition serves, and what each advertised URL must be: https, on
 * the issuer's origin.
 */
function expectValidMetadata(doc: Record<string, unknown>): void {
	expect(doc.issuer).toBe(ISSUER);
	for (const field of [
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	]) {
		expect(doc[field], field).toBeDefined();
	}
	for (const [field, value] of Object.entries(doc)) {
		if (field.endsWith("_endpoint") || field === "jwks_uri") {
			const url = new URL(value as string);
			expect(url.origin, field).toBe(ISSUER);
			expect(url.search + url.hash, field).toBe("");
		}
		if (field.endsWith("_supported") && Array.isArray(value)) {
			expect(value.length, field).toBeGreaterThan(0);
			for (const entry of value) expect(typeof entry, field).toBe("string");
			expect(new Set(value).size, `${field} repeats a value`).toBe(value.length);
		}
	}
	expect(doc.response_types_supported).toEqual(["code"]);
	expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
}

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

const KIB = 1024;

/**
 * A POST whose body has no `Content-Length` — `Transfer-Encoding: chunked`,
 * one KiB a chunk — so only a parser's own running count can bound it.
 * supertest always sets the length, hence a raw request on a real socket.
 */
async function postChunked(
	app: express.Express,
	path: string,
	contentType: string,
	body: string,
	headers: Record<string, string> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
	const server = http.createServer(app);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	try {
		const { port } = server.address() as AddressInfo;
		return await new Promise((resolve, reject) => {
			let answered = false;
			const req = http.request(
				{
					host: "127.0.0.1",
					port,
					path,
					method: "POST",
					// One connection per request, closed after it: nothing keeps the server open.
					agent: false,
					headers: { ...headers, "content-type": contentType, "transfer-encoding": "chunked" },
				},
				(res) => {
					answered = true;
					let text = "";
					res.setEncoding("utf8");
					res.on("data", (chunk: string) => {
						text += chunk;
					});
					res.on("end", () => {
						let parsed: Record<string, unknown> = {};
						try {
							parsed = JSON.parse(text) as Record<string, unknown>;
						} catch {
							// Not JSON: the status carries the verdict.
						}
						resolve({ status: res.statusCode ?? 0, body: parsed });
					});
				},
			);
			// A server that answers 413 mid-body may close the socket while the
			// rest is still being written; that is the answer, not a failure.
			req.on("error", (err) => {
				if (!answered) reject(err);
			});
			for (let at = 0; at < body.length; at += KIB) req.write(body.slice(at, at + KIB));
			req.end();
		});
	} finally {
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
}

const padJson = (bytes: number): string => JSON.stringify({ pad: "a".repeat(bytes) });
const padForm = (bytes: number, fields = "grant_type=client_credentials"): string =>
	`${fields}&pad=${"a".repeat(bytes)}`;

type Send = (
	app: express.Express,
	path: string,
	contentType: string,
	body: string,
	headers?: Record<string, string>,
) => Promise<{ status: number; body: Record<string, unknown> }>;

const withLength: Send = async (app, path, contentType, body, headers = {}) => {
	const res = await request(app)
		.post(path)
		.set(headers)
		.set("Content-Type", contentType)
		.send(body);
	return { status: res.status, body: res.body as Record<string, unknown> };
};

const TRANSFERS: ReadonlyArray<readonly [string, Send]> = [
	["with Content-Length", withLength],
	["chunked", postChunked],
];

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

		it("mounts in a different order from the other case", () => {
			const ids = composed.handle.routes.map((r) => r.contribution.id);
			const grants = ids.indexOf("federation-grants");
			const oauth = ids.indexOf("oauth-endpoints");
			expect(grants >= 0 && oauth >= 0).toBe(true);
			expect(grants < oauth).toBe(order === AS_LISTED);
		});

		it.each(TRANSFERS)(
			"federation grants keep their 16 KiB bound beneath oauthModule's /oauth, a body sent %s",
			async (_transfer, send) => {
				for (const type of ["application/json", "application/x-www-form-urlencoded"]) {
					const body = type === "application/json" ? padJson(40 * KIB) : padForm(40 * KIB);
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
					"application/json",
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
				const form = "application/x-www-form-urlencoded";
				const within = await send(composed.app, "/oauth/token", form, padForm(50 * KIB), headers);
				// Parsed and handed to the grant, which refuses the missing scope.
				expect(within.status).toBe(400);
				expect(within.body.error).toBe("invalid_scope");
				const over = await send(composed.app, "/oauth/token", form, padForm(150 * KIB), headers);
				expect(over.status).toBe(413);
				expect(over.body).toEqual({
					error: "invalid_request",
					error_description: "request body too large",
				});
			},
		);

		it.each(TRANSFERS)(
			"the login route parses past a neighbour's 16 KiB and stops at its own 100 KiB, a body sent %s",
			async (_transfer, send) => {
				const form = "application/x-www-form-urlencoded";
				const fields = `username=${ALICE.username}&password=x`;
				const within = await send(composed.app, "/session/login", form, padForm(50 * KIB, fields));
				// Parsed and handed to the route, whose CSRF check refuses it.
				expect(within.status).toBe(403);
				expect(within.body.error).toBe("access_denied");
				const over = await send(composed.app, "/session/login", form, padForm(150 * KIB, fields));
				expect(over.status).toBe(413);
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
			expect(
				await withLength(app, "/oauth/federation-grants", "application/json", "{nope", grants),
			).toEqual({
				status: 400,
				body: { error: "invalid_request", error_description: "malformed_body" },
			});
			expect(
				await withLength(app, "/session/federation-grants/consent", "application/json", "{nope"),
			).toEqual({
				status: 400,
				body: { error: "invalid_request", error_description: "malformed_body" },
			});
			const token = await withLength(app, "/oauth/token", "application/json", "{nope", {
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
	it.fails.each([
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

interface OutageCase {
	/** The module whose route answers. */
	readonly module: string;
	/** The ComponentMap slot whose store goes down. */
	readonly slot: string;
	readonly surface: string;
	/** Drives the route, taking the store down at the step under test. */
	readonly run: (app: express.Express, outage: Outage, c: Composition) => Promise<request.Response>;
	readonly answer:
		| { readonly status: 503; readonly error: string }
		| { readonly redirect: string; readonly error: "temporarily_unavailable" };
	/**
	 * The name of the one line the outage writes (#685). Absent where the
	 * composition writes no such line today, so that the defect's fix turns
	 * the case red whatever name it gives the line.
	 */
	readonly event?: string;
	/** Warn lines this route writes whatever the store does — not the outage's. */
	readonly unrelatedWarns?: readonly string[];
	/** Set when the composition breaks the contract today: the defect, named. */
	readonly defect?: string;
}

const tokenRequest = (app: express.Express, client: { id: string; secret: string }) =>
	request(app).post("/oauth/token").set("Authorization", basic(client)).type("form");

const OUTAGES: readonly OutageCase[] = [
	{
		module: "oauth-authorization",
		slot: "codeRepository",
		surface: "the code exchange",
		run: async (app, outage) => {
			const { cookies } = await login(app);
			const code = codeFrom(await authorize(app, cookies));
			outage.down = true;
			return redeem(app, code);
		},
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
		run: async (app, outage) => {
			const { refresh_token } = await webTokens(app);
			outage.down = true;
			return tokenRequest(app, WEB).send({ grant_type: "refresh_token", refresh_token });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "refresh_token_store_unavailable",
		unrelatedWarns: ["jwt_verify_aud_skipped"],
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
		defect:
			"core's verifier (`verifyJwt`, packages/core/src/jwt/verify.mts) also writes its own `jwt_verify_rejected` warn with `reason: \"revocation_unavailable\"` for the outage the route logs at error — two lines for one outage; the operator runbook's outage table documents both",
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
		module: "session",
		slot: "userSessionStore",
		surface: "/session/login",
		run: async (app, outage) => {
			outage.down = true;
			return (await login(app)).res;
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		defect:
			"packages/session `Session.mts`: the login route's `userSessionStore.create` failure answers 503 from a bare `catch {}` and logs nothing — a silent 503",
	},
	{
		module: "session",
		slot: "federationTokenStore",
		surface: "the OIDC federation callback",
		run: async (app, outage, c) => {
			const callback = await federatedCallback(app, "oidc", c.upstreams.oidc);
			outage.down = true;
			return callback();
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		defect:
			"packages/session `Federation.mts`: a federation-token-store failure in the callback is not caught; it reaches the terminal handler and is answered `500 server_error`, logged `unhandled_request_error`",
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
		defect:
			"core's rate-limit guard (`packages/core/src/ratelimit/guard.mts`): `rate_limiter_failed_closed` names the limiter by `tag`, not `store` / `step` / `site`, and carries the limiter's error flattened to a string under `error` (the projection's `detail` or `name`), not the projection under `err`",
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
		defect:
			"packages/oauth `routes/authorize.mts`: `authorize_consent_store_unavailable` carries `clientId` and `err` but no `store` / `step` / `site` field naming what failed",
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
		defect:
			'packages/federation-grants: a grant-store failure is answered 503 but logged at warn, as "federation grant operation failed" with a classification and no error projection',
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
		defect:
			'packages/federation-grants: an intent-store failure is answered 503 but logged at warn, as "federation grant operation failed" with a classification and no error projection',
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
		defect:
			"core's JWKS route (`packages/core/src/routes/Jwks.mts`): `jwks_unavailable` carries `algorithm` and `err` but no `store` / `step` / `site` field naming the key store",
	},
];

/** The object argument of a log line, when the line is object-first. */
const fieldsOf = (line: { args: readonly unknown[] }): Record<string, unknown> =>
	typeof line.args[0] === "object" && line.args[0] !== null
		? (line.args[0] as Record<string, unknown>)
		: {};

describe("a store outage answers 503 and is logged once, at error (#685)", () => {
	for (const c of OUTAGES) {
		const title = `${c.module}: ${c.slot} down at ${c.surface}`;
		// A case with a `defect` fails today; `it.fails` keeps it visible and
		// turns red the day the defect is fixed, so the entry is then removed.
		(c.defect === undefined ? it : it.fails)(title, async () => {
			// Everything logged from the moment the store goes down is the outage's.
			let composition: Composition | undefined;
			let from = -1;
			let down = false;
			const outage: Outage = {
				get down() {
					return down;
				},
				set down(value: boolean) {
					if (value && from < 0) from = composition?.logger.lines.length ?? 0;
					down = value;
				},
			};
			composition = await boot({ outage: { slot: c.slot, outage } });
			const res = await c.run(composition.app, outage, composition);
			expect(from, "the case took the store down").toBeGreaterThanOrEqual(0);
			const lines = composition.logger.lines.slice(from);

			if ("status" in c.answer) {
				expect(res.status).toBe(c.answer.status);
				expect(res.body.error).toBe(c.answer.error);
				expect(res.headers["www-authenticate"]).toBeUndefined();
			} else {
				expect(res.status).toBe(302);
				const location = new URL(res.headers.location as string);
				expect(`${location.origin}${location.pathname}`).toBe(c.answer.redirect);
				expect(location.searchParams.get("error")).toBe(c.answer.error);
			}

			const errors = lines.filter((line) => line.level === "error");
			expect(
				errors.map((line) => line.args[1] ?? line.args[0]),
				"exactly one error line",
			).toHaveLength(1);
			const [line] = errors as [LogLine];
			const fields = fieldsOf(line);
			expect(typeof line.args[1], "object-first, with an event name").toBe("string");
			if (c.event !== undefined) expect(line.args[1], "the event name").toBe(c.event);
			expect(
				["store", "step", "site"].some((field) => typeof fields[field] === "string"),
				"a field naming what failed",
			).toBe(true);
			expect(fields.err, "the error's projection").toMatchObject({ name: expect.any(String) });
			expect(fields.err).not.toBeInstanceOf(Error);
			const warns = lines
				.filter((l) => l.level === "warn")
				.map((l) => (typeof l.args[1] === "string" ? l.args[1] : String(l.args[0])))
				.filter((event) => !(c.unrelatedWarns ?? []).includes(event));
			expect(warns, "no warn for the outage").toEqual([]);
		});
	}
});
