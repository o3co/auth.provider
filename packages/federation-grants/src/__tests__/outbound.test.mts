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
 * The federation-grant client routes fetch a `private_key_jwt` client's
 * `jwksUri` through core's outbound fetch, built from the composition's
 * `core.outbound` at boot.
 */

import { generateKeyPairSync, type KeyObject, randomUUID, sign } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type {
	BootstrapMap,
	Client,
	ClientRepository,
	FederationProvider,
} from "@o3co/auth-provider-core";
import {
	createApp,
	createInMemorySubjectRevocation,
	createInMemorySubjectSessionIndex,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	createMemoryReplaySeenSet,
	defineModule,
} from "@o3co/auth-provider-core";
import {
	coreConfigForTests,
	makeValidCoreConfig,
	type OutboundSectionForTests,
	withOutbound,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { federationGrantsModules } from "#/index.mjs";
import {
	ACQUISITION_GRANT_SETTINGS,
	acquisitionComponents,
	callbackUrlFor,
	sessionMiddlewareModule,
} from "./acquisitionFixture.mjs";
import { CLIENT_ID, connection, SUBJECT } from "./harness.mjs";

const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

let privateKey: KeyObject;
let stranger: KeyObject;
let publicJwk: Record<string, unknown>;
let peer: Server;
let jwksUri: string;
const hits: string[] = [];

beforeAll(async () => {
	const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
	privateKey = pair.privateKey;
	stranger = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
	publicJwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "k1", alg: "ES256" };
	peer = createServer((req, res) => {
		hits.push(req.url ?? "");
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ keys: [publicJwk] }));
	});
	await new Promise<void>((resolve) => peer.listen(0, "127.0.0.1", resolve));
	jwksUri = `http://127.0.0.1:${(peer.address() as AddressInfo).port}/jwks`;
});

afterAll(async () => {
	await new Promise<void>((resolve) => peer.close(() => resolve()));
});

afterEach(() => {
	hits.length = 0;
	reasons.length = 0;
	vi.unstubAllEnvs();
});

const INLINE_CLIENT = "inline-app";

const registered = (clientId: string, keys: object) =>
	({
		clientId,
		tokenEndpointAuthMethod: "private_key_jwt",
		allowedScopes: ["openid"],
		defaultScopes: ["openid"],
		allowedGrantTypes: [],
		allowedFederationGrantConnections: [connection.name],
		...keys,
	}) as unknown as Client;

const clientRepository: ClientRepository = {
	findById: async (id) =>
		(id === CLIENT_ID
			? registered(CLIENT_ID, { jwksUri })
			: id === INLINE_CLIENT
				? registered(INLINE_CLIENT, { jwks: { keys: [publicJwk] } })
				: null) as never,
	authenticate: async () => null,
};

/** What each `client_assertion_refused` line gave as its reason. */
const reasons: unknown[] = [];
const logger = {
	trace: () => {},
	debug: () => {},
	info: () => {},
	warn: (line: unknown, event?: unknown) => {
		if (event === "client_assertion_refused") reasons.push((line as { reason?: unknown }).reason);
	},
	error: () => {},
	fatal: () => {},
	child: () => logger,
};

const federationModule = defineModule({
	name: "test-federation-upstream",
	contributes: {
		federations: {
			upstream: () =>
				({
					buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
					exchangeDelegatedCode: async () => ({
						upstream: { issuer: "https://issuer.example", subject: "upstream-1" },
						tokens: {},
					}),
					refreshDelegatedToken: async () => ({}),
				}) as unknown as FederationProvider,
		},
		federationRedirectPolicies: {
			upstream: () => ({
				validateRedirect: () => ({ ok: true as const, value: undefined }),
				resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
			}),
		},
	} as never,
});

const boot = async (outbound?: OutboundSectionForTests) => {
	const base = {
		...makeValidCoreConfig(),
		rateLimit: { failMode: "closed" },
		...coreConfigForTests({
			declaredAbsent: ["auditSink"],
			federations: {
				upstream: {
					enabled: true,
					issuer: connection.upstreamIssuer,
					clientId: connection.upstreamClientId,
				},
			},
		}),
		"federation-grants": {
			enabled: true,
			connections: {
				[connection.name]: {
					federation: "upstream",
					scopes: [...connection.scopes],
					boundary: connection.boundary,
					maxAccessTokenLifetime: connection.maxAccessTokenLifetime,
					callbackURL: callbackUrlFor(connection.name),
				},
			},
			...ACQUISITION_GRANT_SETTINGS,
		},
	};
	const config = outbound === undefined ? base : withOutbound(base, outbound);
	const handle = await createApp({
		modules: [federationModule, sessionMiddlewareModule, ...federationGrantsModules],
		bootstrapComponents: {
			config,
			pathResolver: (s: string) => s,
			logger,
			clientRepository,
			...acquisitionComponents(),
			rateLimiter: createMemoryRateLimiter({
				limits: {},
				defaultLimit: { limit: 100, windowSeconds: 60 },
			}),
			replaySeenSet: createMemoryReplaySeenSet(),
			// What core's federation guard asks for once a federation is enabled.
			userSessionStore: {},
			sessionRPRegistry: {},
			sessionFamilyIndex: {},
			sessionFederationIndex: {},
			federationTokenStore: {},
			refreshTokenFamilyRevocation: {},
			subjectRevocation: createInMemorySubjectRevocation(),
			subjectSessionIndex: createInMemorySubjectSessionIndex(),
			federationGrantStore: createMemoryFederationGrantStore(),
		} as unknown as BootstrapMap,
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

/** A compact ES256 JWS over `claims`, signed with `key`. */
const signed = (claims: Record<string, unknown>, key: KeyObject): string => {
	const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
	const input = `${encode({ alg: "ES256", kid: "k1" })}.${encode(claims)}`;
	const signature = sign("sha256", Buffer.from(input), {
		key,
		dsaEncoding: "ieee-p1363",
	});
	return `${input}.${signature.toString("base64url")}`;
};

const inspect = async (app: express.Express, clientId = CLIENT_ID, key = privateKey) => {
	const now = Math.floor(Date.now() / 1000);
	const assertion = signed(
		{
			iss: clientId,
			sub: clientId,
			aud: `${makeValidCoreConfig().oauth.jwt.issuer}/oauth/token`,
			iat: now,
			exp: now + 60,
			jti: randomUUID(),
		},
		key,
	);
	return request(app).post("/oauth/federation-grants/g-1/status").type("form").send({
		sub: SUBJECT,
		client_assertion_type: ASSERTION_TYPE,
		client_assertion: assertion,
	});
};

/** What a client is shown: the status, the body's bytes and the headers that describe it. */
const shown = (res: request.Response) => ({
	status: res.status,
	text: res.text,
	contentType: res.headers["content-type"],
	wwwAuthenticate: res.headers["www-authenticate"],
});

describe("federation-grant client routes — a client's jwksUri and core.outbound", () => {
	it("authenticates against a key set at a loopback host core.outbound.internalHosts lists", async () => {
		const { handle, app } = await boot({ internalHosts: ["127.0.0.1"] });
		const res = await inspect(app);
		expect(res.status).not.toBe(401);
		expect(res.body.error).not.toBe("invalid_client");
		expect(hits).toEqual(["/jwks"]);
		await handle.dispose();
	});

	it("refuses the same key set without the listing with the bytes a bad signature gets, and never asks it", async () => {
		const { handle, app } = await boot();
		const refused = await inspect(app);
		const badSignature = await inspect(app, INLINE_CLIENT, stranger);
		expect(refused.status).toBe(401);
		expect(refused.body).toEqual({
			error: "invalid_client",
			error_description: "Invalid client assertion",
		});
		expect(shown(refused)).toEqual(shown(badSignature));
		expect(reasons[0]).toBe("jwks_uri_refused");
		const leaked = JSON.stringify({ text: refused.text, headers: refused.headers });
		for (const fragment of ["127.0.0.1", "jwks_uri_refused", "special_use", "scheme_not_allowed"]) {
			expect(leaked).not.toContain(fragment);
		}
		expect(hits).toEqual([]);
		await handle.dispose();
	});

	it("lets core.outbound.deniedHosts win over internalHosts", async () => {
		const { handle, app } = await boot({
			internalHosts: ["127.0.0.1"],
			deniedHosts: ["127.0.0.1"],
		});
		const res = await inspect(app);
		expect(res.status).toBe(401);
		expect(reasons).toEqual(["jwks_uri_refused"]);
		expect(hits).toEqual([]);
		await handle.dispose();
	});

	it("refuses to boot over an egress proxy core.outbound does not state as direct", async () => {
		vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:3128");
		await expect(boot()).rejects.toThrow(/core\.outbound\.egress/);
		const { handle } = await boot({ egress: "direct" });
		await handle.dispose();
	});
});
