/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * A token exchange over HTTP, the way a client makes one: `tokenExchangeModule`
 * composed with `@o3co/auth-provider-oauth`'s `oauthEndpointsModule` through core's
 * `createApp`, and the request POSTed to the real `/oauth/token` route.
 *
 * The other suites call the handler, so this one checks what only the route
 * does: client authentication, dispatch through the resolver and the explicit
 * grant allowlist the handler declares, the response written from the
 * handler's result (status, body, `Cache-Control`, the RFC 6749 §5.2 character
 * set of `error_description`), and how `resource` and `audience` arrive from
 * the route's body parsers. Only what a deployment supplies is stubbed: the
 * client and code repositories and the key store.
 */

import {
	type AppConfig,
	type AppHandle,
	type AuditEvent,
	type ClientRepository,
	type CodeRepository,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	type GrantPolicyDecision,
	jwksModule,
	memoryRefreshTokenFamilyStoreModule,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, renamedVariableCaptures } from "@o3co/auth-provider-core/testing";
import { oauthEndpointsModule } from "@o3co/auth-provider-oauth";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { tokenExchangeModule } from "#/module.mjs";
import { ISSUER, keyStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

const SECRET = "gateway-secret";

/** A confidential client registered for the exchange, as the README's Client configuration shows. */
const gateway: PublicClient = {
	clientId: "client-a",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: ["billing"],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

/** The same kind of client, registered for other grants only. */
const otherGrants: PublicClient = {
	...gateway,
	clientId: "client-b",
	allowedGrantTypes: ["client_credentials"],
};

/** The same kind of client, registered with no `allowedGrantTypes` at all. */
const { allowedGrantTypes: _omitted, ...noGrants } = { ...gateway, clientId: "client-c" };

/**
 * The same kind of client, whose record changes between client
 * authentication and the exchange's own lookup: from its second lookup by
 * id, the repository answers a `clientUri` the registration schema refuses.
 */
const changed: PublicClient = { ...gateway, clientId: "client-d" };
const changedOnLookup = { ...changed, clientUri: "javascript:alert(1)" } as PublicClient;
let lookupsOfChanged = 0;

const clients = new Map<string, PublicClient>(
	[gateway, otherGrants, noGrants, changed].map((client) => [client.clientId, client]),
);

const clientRepository: ClientRepository = {
	findById: async (id) =>
		id === changed.clientId && ++lookupsOfChanged > 1 ? changedOnLookup : (clients.get(id) ?? null),
	authenticate: async (id, secret) => (secret === SECRET ? (clients.get(id) ?? null) : null),
};

/** `oauthEndpointsModule` requires one; nothing here runs the authorization-code flow. */
const codeRepository: CodeRepository = {
	createCode: async () => {
		throw new Error("the authorization-code flow is not exercised here");
	},
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const deploymentProviders = defineModule({
	name: "test:deployment-providers",
	provides: {
		clientRepository: () => clientRepository,
		codeRepository: () => codeRepository,
		keyStore: () => keyStore,
	},
});

function makeConfig(): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		oauth: {
			...base.oauth,
			jwt: { ...base.oauth.jwt, issuer: ISSUER },
			// The oauth module is loaded: its own required key.
			oidcMode: "oidc-required",
			// This composition wires neither the access-token denylist nor the
			// subject watermark, and says so (the boot refuses an undeclared
			// absence).
			revocation: { accessToken: "unsupported", subject: "unsupported" },
		},
	};
}

describe("token exchange through oauthEndpointsModule's POST /oauth/token", () => {
	let handle: AppHandle | undefined;
	afterEach(async () => {
		await handle?.dispose();
		handle = undefined;
	});

	/** The README's "Register the grant" composition, booted for real. */
	async function boot(
		extra: ReadonlyArray<ReturnType<typeof defineModule>> = [],
	): Promise<express.Express> {
		const config = makeConfig();
		const modules = [
			...extra,
			oauthEndpointsModule,
			tokenExchangeModule,
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
			// The exchange requires an issuer, and with one configured the
			// discovery document needs the `jwks_uri` this module contributes.
			jwksModule,
			deploymentProviders,
		];
		handle = await createApp({
			modules,
			bootstrapComponents: {
				// What a resolution of the modules' references under an empty
				// environment captures of the variables they declare renamed.
				config: {
					...config,
					"renamed-variables": {
						...(config as { "renamed-variables"?: object })["renamed-variables"],
						...renamedVariableCaptures({ modules, env: {} }),
					},
				},
				pathResolver: (s: string) => s,
			},
		});
		const app = express();
		app.use(handle.router);
		return app;
	}

	const exchange = (app: express.Express, clientId: string, form: Record<string, string>) =>
		request(app)
			.post("/oauth/token")
			.auth(clientId, SECRET)
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				...form,
			});

	it("carries the subject token's acr, amr and auth_time when this provider issued it", async () => {
		const app = await boot();
		const authTime = Math.floor(Date.now() / 1000) - 60;
		const res = await exchange(app, gateway.clientId, {
			subject_token: await signSelfIssuedAccessToken({
				acr: "urn:o3co:acr:mfa",
				amr: ["pwd", "otp", "mfa"],
				auth_time: authTime,
			}),
			subject_token_type: ACCESS_TOKEN_TYPE,
		});

		expect(res.status).toBe(200);
		expect(decodeJwt(res.body.access_token as string)).toMatchObject({
			iss: ISSUER,
			acr: "urn:o3co:acr:mfa",
			amr: ["pwd", "otp", "mfa"],
			auth_time: authTime,
		});
	});

	it("issues a narrower access token for the requested audience", async () => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({ scope: "read write", aud: "billing" });

		const res = await exchange(app, gateway.clientId, {
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
			audience: "billing",
			scope: "read",
		});

		expect(res.status).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toMatchObject({
			issued_token_type: ACCESS_TOKEN_TYPE,
			token_type: "Bearer",
			scope: "read",
		});
		expect(res.body.expires_in).toBeGreaterThan(0);
		const issued = decodeJwt(res.body.access_token as string);
		expect(issued).toMatchObject({ iss: ISSUER, sub: "user-1", aud: "billing", scope: "read" });
	});

	// The grant denies by absence (README, security note 15). Dispatch refuses
	// a registration naming other grants only with the base check, and one
	// with no `allowedGrantTypes` with the strict check; both answer in the
	// same words, quoting the grant type.
	it.each([
		["names other grants only", otherGrants],
		["omits allowedGrantTypes", noGrants],
	])("refuses a client whose registration %s", async (_case, client) => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({});

		const res = await exchange(app, client.clientId, {
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
		});

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "unauthorized_client",
			error_description: `client is not authorized for grant_type '${TOKEN_EXCHANGE_GRANT_TYPE}'`,
		});
	});

	it("answers a refusal that quotes the request with error_description held to RFC 6749 §5.2", async () => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({});

		// `"` is outside §5.2's character set; the handler quotes the value it
		// refuses, and the route replaces what the set does not allow.
		const res = await exchange(app, gateway.clientId, {
			subject_token: subjectToken,
			subject_token_type: 'urn:example:"quoted"',
		});

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "subject_token_type 'urn:example:?quoted?' is not supported",
		});
	});

	// The slot holds core's client-record boundary, so the exchange's own
	// lookup reads through it too: a record it refuses rejects the lookup,
	// answered as the repository's outage. Client authentication's lookup,
	// the first, read the registration.
	it("answers 503 when the exchange's own lookup reads a record core's boundary refuses", async () => {
		const app = await boot();
		lookupsOfChanged = 0;
		const subjectToken = await signSelfIssuedAccessToken({ scope: "read", aud: "billing" });

		const res = await exchange(app, changed.clientId, {
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
			audience: "billing",
		});

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "client repository unavailable",
		});
	});

	it("refuses a failed client authentication before the grant runs", async () => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({});

		const res = await request(app)
			.post("/oauth/token")
			.auth(gateway.clientId, "wrong-secret")
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
			});

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});

	// The target parameters, RFC 8707 `resource` and RFC 8693 `audience`. The
	// route parses JSON as well as a form, and only a JSON body can carry a
	// value that is neither a string nor an array of strings. Such a value is
	// one the server "fails to parse", which RFC 8707 §2 answers
	// `invalid_target`; it is never converted to a string, because
	// `String([["billing"]])` is `"billing"` — a target the client never sent.
	describe("target parameters", () => {
		const exchangeJson = (app: express.Express, body: Record<string, unknown>) =>
			request(app)
				.post("/oauth/token")
				.auth(gateway.clientId, SECRET)
				.type("json")
				.send({ grant_type: TOKEN_EXCHANGE_GRANT_TYPE, ...body });

		const malformed: ReadonlyArray<readonly [string, unknown]> = [
			["a nested array", [["billing"]]],
			["a number", 42],
			["a boolean", true],
			["an object", { uri: "billing" }],
			["an array holding a number", ["billing", 42]],
			["an array holding null", [null]],
		];

		it.each(malformed)("refuses %s as resource with invalid_target", async (_case, resource) => {
			const app = await boot();
			const subjectToken = await signSelfIssuedAccessToken({ aud: "billing" });

			const res = await exchangeJson(app, {
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource,
			});

			expect(res.status).toBe(400);
			expect(res.body).toEqual({
				error: "invalid_target",
				error_description: "resource must be a string or an array of strings",
			});
		});

		it.each(malformed)("refuses %s as audience with invalid_target", async (_case, audience) => {
			const app = await boot();
			const subjectToken = await signSelfIssuedAccessToken({ aud: "billing" });

			const res = await exchangeJson(app, {
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				audience,
			});

			expect(res.status).toBe(400);
			expect(res.body).toEqual({
				error: "invalid_target",
				error_description: "audience must be a string or an array of strings",
			});
		});

		// RFC 6749 §3.2: a parameter sent without a value is omitted, and the
		// empty entry of a repeated one names nothing — as core reads `resource`
		// for every grant. Either way the issued audience is the one the
		// subject token names, as with the parameter left out.
		const targets = ["resource", "audience"] as const;
		const emptyForms = (name: string): ReadonlyArray<readonly [string, string]> => [
			["sent without a value", `${name}=`],
			["repeated with one empty entry", `${name}=&${name}=billing`],
			["repeated with empty entries only", `${name}=&${name}=`],
		];
		const exchangeForm = (app: express.Express, subjectToken: string, target: string) =>
			request(app)
				.post("/oauth/token")
				.auth(gateway.clientId, SECRET)
				.type("form")
				.send(
					`${new URLSearchParams({
						grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
						subject_token: subjectToken,
						subject_token_type: ACCESS_TOKEN_TYPE,
					}).toString()}&${target}`,
				);

		it.each(
			targets.flatMap((name) =>
				emptyForms(name).map(([shape, target]) => [name, shape, target] as const),
			),
		)("reads a form %s %s by its non-empty values", async (_name, _shape, target) => {
			const app = await boot();
			const subjectToken = await signSelfIssuedAccessToken({ aud: "billing" });

			const res = await exchangeForm(app, subjectToken, target);

			expect(res.status).toBe(200);
			expect(decodeJwt(res.body.access_token as string).aud).toBe("billing");
		});

		it.each(
			targets.flatMap((name) =>
				(
					[
						["null", null],
						["an empty array", []],
						["an array of empty strings", ["", ""]],
					] as const
				).map(([shape, value]) => [name, shape, value] as const),
			),
		)("reads a JSON %s of %s as none requested", async (name, _shape, value) => {
			const app = await boot();
			const subjectToken = await signSelfIssuedAccessToken({ aud: "billing" });

			const res = await exchangeJson(app, {
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				[name]: value,
			});

			expect(res.status).toBe(200);
			expect(decodeJwt(res.body.access_token as string).aud).toBe("billing");
		});

		// The value beside an empty entry is kept, and read: a repeated form
		// `resource` whose one value the issued audience does not equal is
		// refused naming that value, and nothing for the empty entry.
		it("keeps the value beside an empty form entry, and refuses it when the audience does not equal it", async () => {
			const app = await boot();
			const subjectToken = await signSelfIssuedAccessToken({ aud: "billing" });

			const res = await exchangeForm(
				app,
				subjectToken,
				"resource=&resource=https%3A%2F%2Felsewhere.example",
			);

			expect(res.status).toBe(400);
			expect(res.body).toEqual({
				error: "invalid_target",
				error_description: "requested_resources_not_in_audience: https://elsewhere.example",
			});
		});

		it("still refuses a well-formed resource the issued audience does not equal", async () => {
			const app = await boot();
			const subjectToken = await signSelfIssuedAccessToken({ aud: "billing" });

			const res = await exchangeJson(app, {
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				resource: ["billing", "https://elsewhere.example"],
			});

			expect(res.status).toBe(400);
			expect(res.body).toEqual({
				error: "invalid_target",
				error_description: "requested_resources_not_in_audience: https://elsewhere.example",
			});
		});
	});

	// Only an exact "allow" allows and an exact "deny" refuses. Anything else
	// is the deployment's policy at fault: a server error, never a token at
	// the scope the request had before the policy ran, and never a denial.
	describe("a policy decision that is neither allow nor deny", () => {
		const logger = () => {
			const spy = {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
				fatal: vi.fn(),
				child: () => spy,
			};
			return spy;
		};

		it.each([
			["another outcome", { outcome: "denied", error: "access_denied" }],
			["another case", { outcome: "Deny" }],
			["no outcome", {}],
			["null", null],
		])(
			"answers a decision with %s 500 server_error, logs it once and audits a failure",
			async (_label, decision) => {
				const log = logger();
				const events: AuditEvent[] = [];
				const app = await boot([
					defineModule({
						name: "test:grant-policy",
						provides: {
							grantPolicy: () => ({
								kind: "test-policy",
								evaluate: async () => decision as unknown as GrantPolicyDecision,
							}),
						},
					}),
					defineModule({ name: "test:logger", provides: { logger: () => log } }),
					defineModule({
						name: "test:audit-sink",
						provides: {
							auditSink: () => ({
								kind: "spy",
								record: async (event: AuditEvent) => {
									events.push(event);
								},
							}),
						},
					}),
				]);

				const res = await exchange(app, gateway.clientId, {
					subject_token: await signSelfIssuedAccessToken({ scope: "read write" }),
					subject_token_type: ACCESS_TOKEN_TYPE,
				});

				expect(res.status).toBe(500);
				expect(res.body).toEqual({
					error: "server_error",
					error_description: "policy_decision_invalid",
				});
				expect(
					log.error.mock.calls.filter(([, event]) => event === "grant_policy_decision_invalid"),
				).toEqual([
					[
						{ grantType: TOKEN_EXCHANGE_GRANT_TYPE, policy: "test-policy" },
						"grant_policy_decision_invalid",
					],
				]);
				expect(
					events
						.filter((event) => event.type.startsWith("token.issued"))
						.map(({ type, details }) => ({ type, details })),
				).toEqual([
					{
						type: "token.issued.failure",
						details: {
							grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
							error: "server_error",
							reason: "policy_decision_invalid",
						},
					},
				]);
			},
		);
	});

	describe("the refusal's log line — the resources are the caller's", () => {
		// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
		const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

		it("logs the first ten resources, each sanitised and capped, and how many were sent", async () => {
			const logger = {
				trace: vi.fn(),
				debug: vi.fn(),
				info: vi.fn(),
				warn: vi.fn(),
				error: vi.fn(),
				fatal: vi.fn(),
				child: () => logger,
			};
			const app = await boot([
				defineModule({ name: "test:logger", provides: { logger: () => logger } }),
			]);
			const subjectToken = await signSelfIssuedAccessToken({ aud: "billing" });
			// A form body percent-decodes a line break and a control character;
			// twelve resources, the first ten thousand characters long.
			const hostile = `https://x.example\r\nFORGED level=error\u001b[31m${"r".repeat(10_000)}`;
			const resources = [hostile, ...Array.from({ length: 11 }, (_, i) => `https://r${i}.example`)];

			const res = await request(app)
				.post("/oauth/token")
				.auth(gateway.clientId, SECRET)
				.type("form")
				.send(
					[
						`grant_type=${encodeURIComponent(TOKEN_EXCHANGE_GRANT_TYPE)}`,
						`subject_token=${encodeURIComponent(subjectToken)}`,
						`subject_token_type=${encodeURIComponent(ACCESS_TOKEN_TYPE)}`,
						...resources.map((resource) => `resource=${encodeURIComponent(resource)}`),
					].join("&"),
				);

			expect(res.status).toBe(400);
			expect(res.body.error).toBe("invalid_target");
			const lines = logger.warn.mock.calls.filter(
				([, event]) => event === "token_exchange_resource_not_in_audience",
			);
			expect(lines).toHaveLength(1);
			const line = lines[0]?.[0] as { missingResources?: unknown; missingResourceCount?: unknown };
			const logged = Array.isArray(line.missingResources)
				? (line.missingResources as string[])
				: [];
			expect({
				array: Array.isArray(line.missingResources),
				entries: logged.length,
				control: logged.some((entry) => CONTROL.test(entry)),
				within200: logged.every((entry) => entry.length <= 200),
				first: (logged[0] ?? "").slice(0, 25),
				rest: logged.slice(1),
				count: line.missingResourceCount,
			}).toEqual({
				array: true,
				entries: 10,
				control: false,
				within200: true,
				first: "https://x.example??FORGED",
				rest: Array.from({ length: 9 }, (_, i) => `https://r${i}.example`),
				count: 12,
			});
		});
	});
});
