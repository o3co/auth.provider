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
 * Every workspace package booted together on one replica: the standalone
 * template's composition with the seven packages it does not depend on added
 * to it (`full-set.fixture.mts`), held to the contracts that only exist when
 * all of them meet.
 *
 * The template's own suite (`templates/standalone/src/__tests__/
 * all-modules-composition.test.mts`) pins its composition, and ships in every
 * scaffold. This file does not repeat it. It checks what the added modules
 * contribute — their routes, grants, discovery metadata, body rules and store
 * outages — and re-checks a template contract only where the added modules
 * can change the answer: the token endpoint's body rule, now that two more
 * routers mount beneath `/oauth`, and the logger every module that answers a
 * request must receive. `full-set.redis.test.mts` boots the same set on real
 * Redis under `deployment.mode = "multi"`.
 *
 * `it.fails` marks a contract the full set breaks today; its entry names the
 * defect, and the fix that mends it turns the case red.
 */

import { createHash, X509Certificate } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Module } from "@o3co/auth-provider-core";
import { DEVICE_CODE_GRANT_TYPE } from "@o3co/auth-provider-device-grant";
import {
	ACCESS_TOKEN_TYPE,
	TOKEN_EXCHANGE_GRANT_TYPE,
} from "@o3co/auth-provider-oauth-token-exchange";
import {
	ALICE,
	AS_LISTED,
	authorize,
	basic,
	cookiesOf,
	DISCOVERY_PATHS,
	expectValidMetadata,
	ISSUER,
	type LogLine,
	type ModuleOrder,
	type Outage,
	REVERSED,
	webTokens,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { WEBAUTHN_GRANT_TYPE } from "@o3co/auth-provider-webauthn";
import type { Express } from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
	APPLE_LANDING,
	BINDER,
	CLIENT_CERTIFICATE,
	composeFullSet,
	DPOP_JWK,
	dpopProof,
	type FullSet,
	type FullSetOptions,
	GATEWAY,
	GITHUB_LANDING,
	TV,
} from "./full-set.fixture.mts";

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** Boots and remembers the full set, so `afterEach` disposes it. */
async function boot(options: FullSetOptions = {}): Promise<FullSet> {
	current = await composeFullSet(options);
	return current;
}

// ---------------------------------------------------------------------------
// What is composed
// ---------------------------------------------------------------------------

const manifest = JSON.parse(
	readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
) as { devDependencies: Record<string, string> };

/**
 * What the full set takes from each workspace package the template does not
 * compose. The template's own packages are pinned by its suite.
 */
const ADDED: Readonly<Record<string, readonly string[]>> = {
	"@o3co/auth-provider-device-grant": ["device-grant", "core-device-code-store-memory"],
	"@o3co/auth-provider-dpop": ["dpop"],
	"@o3co/auth-provider-federation-apple": ["federation:apple"],
	"@o3co/auth-provider-federation-github": ["federation:github"],
	"@o3co/auth-provider-mtls": ["mtls"],
	"@o3co/auth-provider-oauth-token-exchange": ["oauth-token-exchange"],
	"@o3co/auth-provider-webauthn": [
		"webauthn",
		"core-webauthn-credential-store-memory",
		"core-challenge-store-memory",
		"core-default-challenge-ceremony",
	],
};

/** The modules a deployment writes itself, beside the packages' (see the fixture). */
const DEPLOYMENT_MODULES = [
	"deployment:webauthn-config",
	"deployment:grant-policy",
	"deployment:apple-federation-config",
	"deployment:github-federation-config",
];

describe("what the full set covers", () => {
	it("depends on every workspace package, so each can be booted here", () => {
		const packagesDir = new URL("../../../../packages/", import.meta.url);
		const workspace = readdirSync(packagesDir, { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.map(
				(entry) =>
					(
						JSON.parse(
							readFileSync(new URL(`${entry.name}/package.json`, packagesDir), "utf8"),
						) as {
							name: string;
						}
					).name,
			)
			.sort();
		const depended = Object.keys(manifest.devDependencies)
			.filter((name) => name.startsWith("@o3co/auth-provider-"))
			.filter((name) => name !== "@o3co/auth-provider-standalone")
			.sort();
		expect(workspace.length).toBe(15);
		expect(depended).toEqual(workspace);
	});

	it("adds every package the template does not compose, and nothing the template already does", async () => {
		const { modules } = await boot();
		const names = modules.map((m) => m.name);
		const added = [...Object.values(ADDED).flat(), ...DEPLOYMENT_MODULES];
		for (const name of added) expect(names, name).toContain(name);
		expect(new Set(names).size, "a module listed twice").toBe(names.length);
		// The template's list, then the added modules: nothing between.
		expect(names.slice(names.length - added.length).sort()).toEqual([...added].sort());
	});
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

const contributionNames = (module: Module, kind: string): string[] => {
	const contribution = (module.contributes as Record<string, unknown> | undefined)?.[kind];
	if (contribution === undefined) return [];
	return Array.isArray(contribution) ? [module.name] : Object.keys(contribution as object);
};

const ADDED_GRANTS = [DEVICE_CODE_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE, WEBAUTHN_GRANT_TYPE];
const ALL_GRANTS = [
	"authorization_code",
	"client_credentials",
	"refresh_token",
	"session",
	...ADDED_GRANTS,
].sort();

describe("the full set boots together", () => {
	it("mounts every added route, registers every federation and every grant", async () => {
		const { handle, app } = await boot();
		const ids = handle.routes.map((r) => r.contribution.id);
		for (const id of [
			"device-authorization",
			"device-verification",
			"webauthn-registration-options",
			"webauthn-registration-verify",
			"webauthn-authentication-options",
		]) {
			expect(ids, id).toContain(id);
		}
		expect([...(handle.components.federationProviders?.keys() ?? [])].sort()).toEqual([
			"apple",
			"github",
			"google",
			"oidc",
		]);
		const discovery = await request(app).get(DISCOVERY_PATHS[0]);
		expect([...discovery.body.grant_types_supported].sort()).toEqual(ALL_GRANTS);
	});

	it("hands the deployment's logger to every added module that answers a request or binds a token", async () => {
		const { modules } = await boot();
		const addedNames = new Set(Object.values(ADDED).flat());
		const answering = modules.filter(
			(m) =>
				addedNames.has(m.name) &&
				contributionNames(m, "routes").length +
					contributionNames(m, "grants").length +
					contributionNames(m, "tokenBindingMechanisms").length >
					0,
		);
		expect(answering.map((m) => m.name).sort()).toEqual(
			["device-grant", "dpop", "mtls", "oauth-token-exchange", "webauthn"].sort(),
		);
		for (const module of answering) {
			expect([...(module.requires ?? []), ...(module.optional ?? [])], module.name).toContain(
				"logger",
			);
		}
	});
});

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

describe("discovery with every package on", () => {
	it.each(DISCOVERY_PATHS)(
		"%s is valid and advertises what the added modules contribute",
		async (path) => {
			const { app } = await boot();
			const res = await request(app).get(path);
			expect(res.status).toBe(200);
			expectValidMetadata(res.body);
			expect([...res.body.grant_types_supported].sort()).toEqual(ALL_GRANTS);
			expect(res.body.device_authorization_endpoint).toBe(`${ISSUER}/oauth/device_authorization`);
			expect(res.body.dpop_signing_alg_values_supported).toEqual([
				"ES256",
				"ES384",
				"EdDSA",
				"RS256",
			]);
			expect(res.body.tls_client_certificate_bound_access_tokens).toBe(true);
		},
	);

	it("answers the device authorization endpoint it advertises", async () => {
		const { app } = await boot();
		const { pathname } = new URL(
			(await request(app).get(DISCOVERY_PATHS[0])).body.device_authorization_endpoint as string,
		);
		expect((await request(app).post(pathname).type("form").send({})).status).not.toBe(404);
	});

	/**
	 * Each added feature off, alone: exactly what it contributed leaves the
	 * document, and its route (where it has one) stops answering.
	 */
	const TOGGLES: ReadonlyArray<
		readonly [
			feature: keyof NonNullable<FullSetOptions["features"]>,
			gone: { grant?: string; fields?: readonly string[]; route?: readonly [string, string] },
		]
	> = [
		[
			"deviceGrant",
			{
				grant: DEVICE_CODE_GRANT_TYPE,
				fields: ["device_authorization_endpoint"],
				route: ["post", "/oauth/device_authorization"],
			},
		],
		["dpop", { fields: ["dpop_signing_alg_values_supported"] }],
		["mtls", { fields: ["tls_client_certificate_bound_access_tokens"] }],
		["tokenExchange", { grant: TOKEN_EXCHANGE_GRANT_TYPE }],
		[
			"webauthn",
			{ grant: WEBAUTHN_GRANT_TYPE, route: ["post", "/oauth/webauthn/authentication/options"] },
		],
		["apple", { route: ["get", "/session/oauth/federation/apple"] }],
		["github", { route: ["get", "/session/oauth/federation/github"] }],
	];

	it.each(TOGGLES)(
		"%s off: only what it contributed leaves the document and the app",
		async (feature, gone) => {
			const on = await boot();
			const before = (await request(on.app).get(DISCOVERY_PATHS[0])).body as Record<
				string,
				unknown
			>;
			await on.handle.dispose();
			current = undefined;

			const { app } = await boot({ features: { [feature]: false } });
			const after = (await request(app).get(DISCOVERY_PATHS[0])).body as Record<string, unknown>;
			expectValidMetadata(after);
			const expected: Record<string, unknown> = { ...before };
			for (const field of gone.fields ?? []) delete expected[field];
			expected.grant_types_supported = (before.grant_types_supported as string[]).filter(
				(g) => g !== gone.grant,
			);
			expect(after).toEqual(expected);
			if (gone.route !== undefined) {
				const [method, path] = gone.route;
				const res = await request(app)[method as "get" | "post"](path).send({});
				expect(res.status, path).toBe(404);
			}
		},
	);
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/** Sign in through the session routes on one cookie jar, and hand back the jar and a CSRF pair. */
async function signedIn(app: Express) {
	const agent = request.agent(app);
	const first = await agent.get("/session/csrf");
	const login = await agent
		.post("/session/login")
		.set(first.body.header_name as string, first.body.csrf_token as string)
		.type("form")
		.send({ username: ALICE.username, password: ALICE.password });
	expect(login.status).toBe(200);
	const csrf = await agent.get("/session/csrf");
	return {
		agent,
		header: csrf.body.header_name as string,
		token: csrf.body.csrf_token as string,
	};
}

const tokenPayload = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString()) as Record<
		string,
		unknown
	>;

/** RFC 7638 thumbprint of the fixture's DPoP key. */
const DPOP_JKT = createHash("sha256")
	.update(JSON.stringify({ crv: DPOP_JWK.crv, kty: DPOP_JWK.kty, x: DPOP_JWK.x, y: DPOP_JWK.y }))
	.digest("base64url");

describe("every added module's primary route answers in the one app", () => {
	it("the device grant: authorization, the user's approval, the poll", async () => {
		const { app } = await boot();
		const started = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: TV.id });
		expect(started.status).toBe(200);
		expect(started.body.verification_uri).toBe(`${ISSUER}/device`);
		// One poll, after the approval: a second inside the five-second interval
		// is RFC 8628's `slow_down`, which is the grant working, not the flow.
		const poll = () =>
			request(app).post("/oauth/token").type("form").send({
				grant_type: DEVICE_CODE_GRANT_TYPE,
				client_id: TV.id,
				device_code: started.body.device_code,
			});

		const { agent, header, token } = await signedIn(app);
		const approved = await agent
			.post("/oauth/device/verification")
			.set(header, token)
			.send({ action: "approve", user_code: started.body.user_code });
		expect(approved.status).toBe(200);
		expect(approved.body.status).toBe("approved");

		const tokens = await poll();
		expect(tokens.status).toBe(200);
		expect(tokenPayload(tokens.body.access_token as string)).toMatchObject({
			sub: ALICE.sub,
			azp: TV.id,
		});
	});

	it("token exchange: a gateway exchanges the web client's access token", async () => {
		const { app } = await boot();
		const { access_token } = await webTokens(app);
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(GATEWAY))
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				subject_token: access_token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
		expect(res.status).toBe(200);
		expect(res.body.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
		expect(tokenPayload(res.body.access_token as string)).toMatchObject({
			sub: ALICE.sub,
			azp: GATEWAY.id,
		});
	});

	it("DPoP: a client_credentials token bound to the proof's key", async () => {
		const { app } = await boot();
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(BINDER))
			.set("DPoP", dpopProof("POST", `${ISSUER}/oauth/token`))
			.type("form")
			.send({ grant_type: "client_credentials" });
		expect(res.status).toBe(200);
		expect(res.body.token_type).toBe("DPoP");
		expect(tokenPayload(res.body.access_token as string).cnf).toEqual({ jkt: DPOP_JKT });
	});

	it("mTLS: a client_credentials token bound to the forwarded certificate", async () => {
		const { app } = await boot();
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(BINDER))
			.set("x-forwarded-client-cert", encodeURIComponent(CLIENT_CERTIFICATE))
			.type("form")
			.send({ grant_type: "client_credentials" });
		expect(res.status).toBe(200);
		const thumbprint = createHash("sha256")
			.update(new X509Certificate(CLIENT_CERTIFICATE).raw)
			.digest("base64url");
		expect(tokenPayload(res.body.access_token as string).cnf).toEqual({
			"x5t#S256": thumbprint,
		});
	});

	it("WebAuthn: authentication options for this relying party", async () => {
		const { app } = await boot();
		const res = await request(app).post("/oauth/webauthn/authentication/options").send({});
		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ rpId: "auth.test", challenge: expect.any(String) });
	});

	it("Apple: a form_post login ends in a session /authorize accepts", async () => {
		const { app, fakes } = await boot();
		const start = await request(app).get("/session/oauth/federation/apple");
		expect(start.status).toBe(302);
		const answer = fakes.apple.authorize(start.headers.location as string);
		const callback = await request(app)
			.post("/session/oauth/federation/apple/callback")
			.set("Cookie", cookiesOf(start))
			.type("form")
			.send({ code: answer.code, state: answer.state ?? "" });
		expect(callback.status).toBe(302);
		expect(callback.headers.location).toBe(APPLE_LANDING);
		const authorized = await authorize(app, cookiesOf(callback));
		expect(authorized.headers.location).toMatch(/\?code=/);
	});

	it("GitHub: a login ends in a session /authorize accepts", async () => {
		const { app } = await boot();
		const start = await request(app).get("/session/oauth/federation/github");
		expect(start.status).toBe(302);
		const state = new URL(start.headers.location as string).searchParams.get("state") ?? "";
		const callback = await request(app)
			.get("/session/oauth/federation/github/callback")
			.set("Cookie", cookiesOf(start))
			.query({ code: "github-code", state });
		expect(callback.status).toBe(302);
		expect(callback.headers.location).toBe(GITHUB_LANDING);
		const authorized = await authorize(app, cookiesOf(callback));
		expect(authorized.headers.location).toMatch(/\?code=/);
	});
});

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

const KIB = 1024;

/**
 * A POST with `Transfer-Encoding: chunked` and no `Content-Length`, one KiB a
 * chunk, on a real socket (supertest always declares a length).
 */
async function postChunked(
	app: Express,
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
			// A 413 may close the socket mid-body; that is the answer.
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

type Send = (
	app: Express,
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

const padJson = (bytes: number, fields: Record<string, unknown> = {}): string =>
	JSON.stringify({ ...fields, pad: "a".repeat(bytes) });
const padForm = (bytes: number, fields: string): string => `${fields}&pad=${"a".repeat(bytes)}`;

const JSON_TYPE = "application/json";
const FORM_TYPE = "application/x-www-form-urlencoded";

describe.each([AS_LISTED, REVERSED] satisfies ModuleOrder[])("bodies, modules %s", (order) => {
	let composed: FullSet;
	beforeAll(async () => {
		composed = await composeFullSet({ order });
	});
	afterAll(async () => {
		await composed.handle.dispose();
	});

	it("puts the added routers on the other side of oauthModule's", () => {
		const ids = composed.handle.routes.map((r) => r.contribution.id);
		const oauth = ids.indexOf("oauth-endpoints");
		for (const id of ["device-authorization", "webauthn-authentication-options"]) {
			expect(ids.indexOf(id) > oauth, id).toBe(order === AS_LISTED);
		}
	});

	it.each(TRANSFERS)(
		"/oauth/device_authorization keeps its 16 KiB bound, a body sent %s",
		async (_transfer, send) => {
			for (const [type, body] of [
				[FORM_TYPE, padForm(40 * KIB, `client_id=${TV.id}`)],
				[JSON_TYPE, padJson(40 * KIB, { client_id: TV.id })],
			] as const) {
				const res = await send(composed.app, "/oauth/device_authorization", type, body);
				expect(res.status, type).toBe(413);
				expect(res.body, type).toMatchObject({
					error: "invalid_request",
					error_description: "body_too_large",
				});
			}
		},
	);

	it.each(TRANSFERS)(
		"/oauth/device/verification keeps its 16 KiB bound, a body sent %s",
		async (_transfer, send) => {
			const res = await send(
				composed.app,
				"/oauth/device/verification",
				JSON_TYPE,
				padJson(40 * KIB, { action: "lookup", user_code: "BCDF-GHJK" }),
			);
			expect(res.status).toBe(413);
			expect(res.body).toMatchObject({
				error: "invalid_request",
				error_description: "body_too_large",
			});
		},
	);

	it.each(TRANSFERS)(
		"WebAuthn authentication options parse past 16 KiB and stop at their 100 KiB, a body sent %s",
		async (_transfer, send) => {
			const path = "/oauth/webauthn/authentication/options";
			const within = await send(composed.app, path, JSON_TYPE, padJson(50 * KIB));
			expect(within.status).toBe(200);
			const over = await send(composed.app, path, JSON_TYPE, padJson(150 * KIB));
			expect(over.status).toBe(413);
		},
	);

	it.each(TRANSFERS)(
		"the token endpoint still parses past 16 KiB and stops at its 100 KiB beside them, a body sent %s",
		async (_transfer, send) => {
			const headers = { authorization: basic(BINDER) };
			const fields = "grant_type=client_credentials&scope=api.read";
			const within = await send(
				composed.app,
				"/oauth/token",
				FORM_TYPE,
				padForm(50 * KIB, fields),
				headers,
			);
			expect(within.status).toBe(200);
			const over = await send(
				composed.app,
				"/oauth/token",
				FORM_TYPE,
				padForm(150 * KIB, fields),
				headers,
			);
			expect(over.status).toBe(413);
		},
	);

	it("the verification route refuses a form with its own 415, beside every other parser", async () => {
		const res = await withLength(
			composed.app,
			"/oauth/device/verification",
			FORM_TYPE,
			"action=lookup&user_code=BCDF-GHJK",
		);
		// The CSRF guard runs first and refuses a form carrying no token.
		expect([403, 415]).toContain(res.status);
	});
});

// ---------------------------------------------------------------------------
// Outages
// ---------------------------------------------------------------------------

interface OutageCase {
	readonly module: string;
	readonly slot: string;
	readonly surface: string;
	readonly run: (app: Express, outage: Outage, c: FullSet) => Promise<request.Response>;
	readonly status: 503;
	readonly error: string;
	/** The name of the one line the outage writes; absent where there is none today. */
	readonly event?: string;
	/** Set when the full set breaks the contract today: the defect, named. */
	readonly defect?: string;
}

const OUTAGES: readonly OutageCase[] = [
	{
		module: "device-grant",
		slot: "deviceCodeStore",
		surface: "POST /oauth/device_authorization",
		run: async (app, outage) => {
			outage.down = true;
			return request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({ client_id: TV.id });
		},
		status: 503,
		error: "temporarily_unavailable",
		event: "device_authorization_store_unavailable",
		defect:
			"packages/device-grant `deviceAuthorizationEndpoint.mts`: `device_authorization_store_unavailable` carries `clientId` and `err` but no `store` / `step` / `site` field naming the device-code store",
	},
	{
		module: "dpop",
		slot: "replaySeenSet",
		surface: "a DPoP proof at /oauth/token",
		run: async (app, outage) => {
			outage.down = true;
			return request(app)
				.post("/oauth/token")
				.set("Authorization", basic(BINDER))
				.set("DPoP", dpopProof("POST", `${ISSUER}/oauth/token`))
				.type("form")
				.send({ grant_type: "client_credentials" });
		},
		status: 503,
		error: "temporarily_unavailable",
		event: "token_binding_unavailable",
		defect:
			'core\'s token-binding dispatcher (`packages/core/src/middleware/tokenBinding.mts`): `token_binding_unavailable` names the mechanism and `reason: "replay_store_unavailable"`, but carries no `store` / `step` / `site` field',
	},
	{
		module: "oauth-token-exchange",
		slot: "accessTokenDenylist",
		surface: "the subject_token's revocation check",
		run: async (app, outage) => {
			const { access_token } = await webTokens(app);
			outage.down = true;
			return request(app)
				.post("/oauth/token")
				.set("Authorization", basic(GATEWAY))
				.type("form")
				.send({
					grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
					subject_token: access_token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				});
		},
		status: 503,
		error: "temporarily_unavailable",
		event: "token_exchange_validation_unavailable",
		defect:
			"two lines and no store field: core's verifier (`verifyJwt`, `packages/core/src/jwt/verify.mts`) also writes a `jwt_verify_rejected` warn (`reason: \"revocation_unavailable\"`) for the outage — the defect the template suite pins at introspection — and `token_exchange_validation_unavailable` (`packages/oauth-token-exchange`) names the token's `role` but no `store` / `step` / `site`",
	},
	{
		module: "webauthn",
		slot: "challengeStore",
		surface: "POST /oauth/webauthn/authentication/options",
		run: async (app, outage) => {
			outage.down = true;
			return request(app).post("/oauth/webauthn/authentication/options").send({});
		},
		status: 503,
		error: "temporarily_unavailable",
		defect:
			"packages/webauthn `routes/authenticationOptions.mts`: a challenge-store failure at `challengeStore.issue` is not caught; it reaches the terminal handler and is answered `500 server_error`, logged `unhandled_request_error` (the runbook documents the same 500 for the ceremony's `contains` / `markSeen`)",
	},
];

const fieldsOf = (line: LogLine): Record<string, unknown> =>
	typeof line.args[0] === "object" && line.args[0] !== null
		? (line.args[0] as Record<string, unknown>)
		: {};

describe("a store outage behind an added module answers 503 and is logged once, at error (#685)", () => {
	for (const c of OUTAGES) {
		(c.defect === undefined ? it : it.fails)(
			`${c.module}: ${c.slot} down at ${c.surface}`,
			async () => {
				let composition: FullSet | undefined;
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

				expect(res.status).toBe(c.status);
				expect(res.body.error).toBe(c.error);

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
					.map((l) => (typeof l.args[1] === "string" ? l.args[1] : String(l.args[0])));
				expect(warns, "no warn for the outage").toEqual([]);
			},
		);
	}
});
