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
 * The composed OAuth router fetches every URL a client registration names —
 * a back-channel logout URI, a `jwksUri` — through core's outbound fetch,
 * built once from the router's `core.outbound`: the section reaches
 * `/oauth/token`, `/oauth/introspect`, `/oauth/revoke` and `/oauth/logout`,
 * and a malformed section or an unstated egress proxy refuses the build.
 */

import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
	type AppConfig,
	type ClientRepository,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	type FederationTokenStore,
	type Logger,
	type PublicClient,
	type RefreshTokenFamilyRevocation,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	GrantRegistry,
	type OutboundSectionForTests,
	resolverForTests,
	withOutbound,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example.com";
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const RP_ID = "rp-app";
const JWT_CLIENT = "jwt-app";
const INLINE_CLIENT = "jwt-inline";
const SID = "sid-outbound";
const SUB = "user-outbound";

const keyStore = createSymmetricKeyStore(SECRET);
const baseConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
};

let signing: { privateKey: CryptoKey; publicJwk: JWK };
let stranger: CryptoKey;

/** A loopback peer: it serves a key set, a back-channel endpoint, a redirect and an oversized answer, and records every path it is asked for. */
let peer: Server;
let origin: string;
const hits: string[] = [];

beforeAll(async () => {
	const pair = await generateKeyPair("ES256");
	signing = {
		privateKey: pair.privateKey,
		publicJwk: { ...(await exportJWK(pair.publicKey)), kid: "k1" },
	};
	stranger = (await generateKeyPair("ES256")).privateKey;
	peer = createServer((req, res) => {
		hits.push(req.url ?? "");
		req.resume();
		if (req.url === "/jwks") {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ keys: [signing.publicJwk] }));
		} else if (req.url === "/big") {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ keys: [signing.publicJwk], padding: "x".repeat(4096) }));
		} else if (req.url === "/redirect") {
			res.writeHead(307, { location: "/landed" });
			res.end();
		} else {
			res.writeHead(204);
			res.end();
		}
	});
	await new Promise<void>((resolve) => peer.listen(0, "127.0.0.1", resolve));
	origin = `http://127.0.0.1:${(peer.address() as AddressInfo).port}`;
});

afterAll(async () => {
	await new Promise<void>((resolve) => peer.close(() => resolve()));
});

afterEach(() => {
	hits.length = 0;
	vi.unstubAllEnvs();
});

const LISTED: OutboundSectionForTests = { internalHosts: ["127.0.0.1"] };

interface Built {
	readonly app: express.Express;
	readonly warnings: { line: Record<string, unknown>; event: string }[];
}

const configWith = (outbound?: OutboundSectionForTests): AppConfig =>
	(outbound === undefined
		? baseConfig
		: withOutbound(baseConfig, outbound)) as unknown as AppConfig;

async function build(
	opts: { outbound?: OutboundSectionForTests; jwksUri?: string; backchannelUri?: string } = {},
): Promise<Built> {
	const warnings: Built["warnings"] = [];
	const record = (line: unknown, event?: unknown) => {
		if (typeof line === "object" && line !== null && typeof event === "string") {
			warnings.push({ line: line as Record<string, unknown>, event });
		}
	};
	const logger: Logger = {
		trace: () => {},
		debug: () => {},
		info: () => {},
		warn: record,
		error: record,
		fatal: () => {},
		child: () => logger,
	};
	const clients: Record<string, PublicClient> = {
		[RP_ID]: {
			clientId: RP_ID,
			tokenEndpointAuthMethod: "client_secret_basic",
			allowedRedirectUris: [],
			allowedScopes: [],
			postLogoutRedirectUris: [],
		} as PublicClient,
		[JWT_CLIENT]: {
			clientId: JWT_CLIENT,
			tokenEndpointAuthMethod: "private_key_jwt",
			allowedRedirectUris: [],
			allowedScopes: [],
			...(opts.jwksUri === undefined ? {} : { jwksUri: opts.jwksUri }),
		} as PublicClient,
		[INLINE_CLIENT]: {
			clientId: INLINE_CLIENT,
			tokenEndpointAuthMethod: "private_key_jwt",
			allowedRedirectUris: [],
			allowedScopes: [],
			jwks: { keys: [signing.publicJwk] },
		} as PublicClient,
	};
	const clientRepository: ClientRepository = {
		findById: async (id) => (clients[id] as never) ?? null,
		authenticate: async () => null,
	};
	const userSessionStore = {
		kind: "memory",
		create: async () => {},
		get: async (sid: string) =>
			sid === SID
				? {
						sid: SID,
						sub: SUB,
						authTime: new Date(),
						createdAt: new Date(),
						expiresAt: new Date(Date.now() + 3_600_000),
						claims: {},
						amr: undefined,
						authentication: undefined,
					}
				: null,
		delete: async () => {},
	} as unknown as UserSessionStore;
	const rps =
		opts.backchannelUri === undefined
			? []
			: [
					{
						clientId: RP_ID,
						backchannelLogoutUri: opts.backchannelUri,
						backchannelLogoutSessionRequired: true,
						registeredAt: new Date(),
					},
				];
	const { router } = await createOAuthRouter(express, {
		requirements: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		registry: new GrantRegistry(),
		config: configWith(opts.outbound),
		clientRepository,
		keyStore,
		replaySeenSet: createMemoryReplaySeenSet(),
		logger,
		userSessionStore,
		sessionRPRegistry: {
			kind: "memory",
			registerRP: async () => {},
			listRPs: async () => rps,
			removeBySid: async () => {},
		} as unknown as SessionRPRegistry,
		sessionFamilyIndex: {
			kind: "memory",
			addFamilyId: async () => {},
			listFamilyIds: async () => [],
			removeBySid: async () => {},
		} as unknown as SessionFamilyIndex,
		sessionFederationIndex: {
			kind: "memory",
			addFederation: async () => {},
			listFederations: async () => [],
			removeFederation: async () => {},
			removeBySid: async () => {},
		} as unknown as SessionFederationIndex,
		federationTokenStore: {
			kind: "memory",
			attach: async () => {},
			get: async () => null,
			update: async () => {},
			delete: async () => {},
			removeBySid: async () => {},
		} as unknown as FederationTokenStore,
		refreshTokenFamilyRevocation: {
			isFamilyRevoked: async () => false,
			revokeFamily: async () => {},
		} as unknown as RefreshTokenFamilyRevocation,
	});
	const app = express();
	app.use("/oauth", router);
	return { app, warnings };
}

const assertion = async (clientId: string, key: CryptoKey = signing.privateKey) => {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({
		iss: clientId,
		sub: clientId,
		aud: TOKEN_ENDPOINT,
		iat: now,
		exp: now + 60,
		jti: randomUUID(),
	})
		.setProtectedHeader({ alg: "ES256", kid: "k1" })
		.sign(key);
};

const ENDPOINTS = [
	["/oauth/token", { grant_type: "client_credentials" }],
	["/oauth/introspect", { token: "not-a-token" }],
	["/oauth/revoke", { token: "not-a-token" }],
] as const;

const authenticate = async (
	app: express.Express,
	path: string,
	form: Readonly<Record<string, string>>,
	clientId = JWT_CLIENT,
	key?: CryptoKey,
) =>
	request(app)
		.post(path)
		.type("form")
		.send({
			...form,
			client_assertion_type: ASSERTION_TYPE,
			client_assertion: await assertion(clientId, key),
		});

/** What a client is shown: the status, the body's bytes and the headers that describe it. */
const shown = (res: request.Response) => ({
	status: res.status,
	text: res.text,
	contentType: res.headers["content-type"],
	wwwAuthenticate: res.headers["www-authenticate"],
});

const refusals = (built: Built) =>
	built.warnings.filter((w) => w.event === "client_assertion_refused").map((w) => w.line.reason);

describe("private_key_jwt key sets through the composed router", () => {
	describe.each(ENDPOINTS)("%s", (path, form) => {
		it.each([
			"https://127.0.0.1/jwks",
			"https://[::ffff:127.0.0.1]/jwks",
			"https://u:p@rp.example.test/jwks",
		])("answers a refused jwks_uri (%s) with the bytes a bad signature gets", async (jwksUri) => {
			const built = await build({ jwksUri });
			const refused = await authenticate(built.app, path, form);
			const badSignature = await authenticate(built.app, path, form, INLINE_CLIENT, stranger);

			expect(refused.status).toBe(401);
			expect(refused.body).toEqual({
				error: "invalid_client",
				error_description: "Invalid client assertion",
			});
			expect(shown(refused)).toEqual(shown(badSignature));
			expect(refusals(built)).toContain("jwks_uri_refused");
			const leaked = JSON.stringify({ text: refused.text, headers: refused.headers });
			for (const fragment of ["127.0.0.1", "rp.example.test", "jwks_uri_refused", "special_use"]) {
				expect(leaked).not.toContain(fragment);
			}
		});

		it("verifies under a key set at a loopback host core.outbound.internalHosts lists", async () => {
			const built = await build({ outbound: LISTED, jwksUri: `${origin}/jwks` });
			const res = await authenticate(built.app, path, form);
			expect(res.status).not.toBe(401);
			expect(res.body.error).not.toBe("invalid_client");
			expect(hits).toEqual(["/jwks"]);
		});

		it("refuses the same key set without the listing, and never asks it", async () => {
			const built = await build({ jwksUri: `${origin}/jwks` });
			const res = await authenticate(built.app, path, form);
			expect(res.status).toBe(401);
			expect(refusals(built)).toEqual(["jwks_uri_refused"]);
			expect(hits).toEqual([]);
		});

		it("lets core.outbound.deniedHosts win over internalHosts", async () => {
			const built = await build({
				outbound: { ...LISTED, deniedHosts: ["127.0.0.1"] },
				jwksUri: `${origin}/jwks`,
			});
			const res = await authenticate(built.app, path, form);
			expect(res.status).toBe(401);
			expect(refusals(built)).toEqual(["jwks_uri_refused"]);
			expect(hits).toEqual([]);
		});
	});

	it("refuses a key set over core.outbound.maxResponseBytes", async () => {
		const built = await build({
			outbound: { ...LISTED, maxResponseBytes: 1024 },
			jwksUri: `${origin}/big`,
		});
		const res = await authenticate(built.app, "/oauth/token", ENDPOINTS[0][1]);
		expect(res.status).toBe(401);
		expect(res.body.error_description).toBe("Invalid client assertion");
		expect(refusals(built)).toEqual(["jwks_uri_refused"]);
	});

	it("refuses a key set that redirects, and never follows it", async () => {
		const built = await build({ outbound: LISTED, jwksUri: `${origin}/redirect` });
		const res = await authenticate(built.app, "/oauth/token", ENDPOINTS[0][1]);
		expect(res.status).toBe(401);
		expect(refusals(built)).toEqual(["jwks_uri_refused"]);
		expect(hits).toEqual(["/redirect"]);
	});
});

describe("back-channel logout through the composed router", () => {
	const logout = async (built: Built) => {
		const hint = await new SignJWT({ sub: SUB, aud: RP_ID, sid: SID })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "JWT" })
			.setIssuer(ISSUER)
			.setIssuedAt()
			.setExpirationTime("1h")
			.sign(new TextEncoder().encode(SECRET));
		return request(built.app).post("/oauth/logout").type("form").send({ id_token_hint: hint });
	};

	const failures = (built: Built) =>
		built.warnings.filter((w) => w.event === "logout_backchannel_failed").map((w) => w.line.step);

	it("posts to a loopback RP core.outbound.internalHosts lists", async () => {
		const built = await build({ outbound: LISTED, backchannelUri: `${origin}/bc` });
		expect((await logout(built)).status).toBe(200);
		expect(hits).toEqual(["/bc"]);
		expect(failures(built)).toEqual([]);
	});

	it("treats an unlisted http RP as unreachable, and the logout still completes", async () => {
		const built = await build({ backchannelUri: `${origin}/bc` });
		expect((await logout(built)).status).toBe(200);
		expect(hits).toEqual([]);
		expect(failures(built)).toEqual(["destination"]);
	});

	it("lets core.outbound.deniedHosts win over internalHosts", async () => {
		const built = await build({
			outbound: { ...LISTED, deniedHosts: ["127.0.0.1"] },
			backchannelUri: `${origin}/bc`,
		});
		expect((await logout(built)).status).toBe(200);
		expect(hits).toEqual([]);
		expect(failures(built)).toEqual(["destination"]);
	});

	it("does not follow an RP's redirect", async () => {
		const built = await build({ outbound: LISTED, backchannelUri: `${origin}/redirect` });
		expect((await logout(built)).status).toBe(200);
		expect(hits).toEqual(["/redirect"]);
		expect(failures(built)).toEqual(["destination"]);
	});

	it("treats an answer over core.outbound.maxResponseBytes as unreachable", async () => {
		const built = await build({
			outbound: { ...LISTED, maxResponseBytes: 1024 },
			backchannelUri: `${origin}/big`,
		});
		expect((await logout(built)).status).toBe(200);
		expect(failures(built)).toEqual(["destination"]);
	});
});

describe("building the router", () => {
	it("refuses a malformed core.outbound, naming the key", async () => {
		await expect(
			build({ outbound: { allowedHosts: ["not a host"] } as OutboundSectionForTests }),
		).rejects.toThrow(/core\.outbound\.allowedHosts/);
	});

	it("refuses an egress proxy core.outbound does not state as direct", async () => {
		vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:3128");
		await expect(build()).rejects.toThrow(/core\.outbound\.egress/);
	});

	it("builds with an egress proxy once core.outbound.egress is direct", async () => {
		vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:3128");
		await expect(build({ outbound: { egress: "direct" } })).resolves.toBeDefined();
	});
});
