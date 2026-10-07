/**
 * The composed OAuth router fetches a client's `jwksUri` through core's
 * outbound fetch, built once from the `outboundPolicy` it is handed: the
 * policy reaches `/oauth/token`, `/oauth/introspect` and `/oauth/revoke`, and
 * an unstated egress proxy refuses the build.
 */

import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
	type ClientRepository,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	type Logger,
	type PublicClient,
} from "@o3co/auth-provider-core";
import {
	createTestOutboundPolicy,
	GrantRegistry,
	type OutboundSectionForTests,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { routerInputsOf } from "./_helpers/sections.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example.com";
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const JWT_CLIENT = "jwt-app";
const INLINE_CLIENT = "jwt-inline";

const keyStore = createSymmetricKeyStore(SECRET);
const baseConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { defaultExpiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		revocation: { accessToken: "unsupported" },
	},
};

let signing: { privateKey: CryptoKey; publicJwk: JWK };
let stranger: CryptoKey;

/** A loopback peer: it serves a key set, a redirect and an oversized answer, and records every path it is asked for. */
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
			res.writeHead(307, { location: "/jwks" });
			res.end();
		} else {
			res.writeHead(404);
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

async function build(
	opts: { outbound?: OutboundSectionForTests; jwksUri?: string } = {},
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
	const { router } = await createOAuthRouter(express, {
		requirements: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		registry: new GrantRegistry(),
		...routerInputsOf(baseConfig),
		outboundPolicy: createTestOutboundPolicy(opts.outbound),
		clientRepository,
		keyStore,
		replaySeenSet: createMemoryReplaySeenSet(),
		logger,
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

describe("building the router", () => {
	it("refuses an egress proxy core.outbound does not state as direct", async () => {
		vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:3128");
		await expect(build()).rejects.toThrow(/core\.outbound\.egress/);
	});

	it("builds with an egress proxy once core.outbound.egress is direct", async () => {
		vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:3128");
		await expect(build({ outbound: { egress: "direct" } })).resolves.toBeDefined();
	});
});
