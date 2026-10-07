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
 * The device authorization endpoint fetches a `private_key_jwt` client's
 * `jwksUri` through core's outbound fetch, built from the `outboundPolicy`
 * slot core fills from the composition's `core.outbound`.
 */

import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
	type BootstrapMap,
	type ClientRepository,
	createApp,
	createInMemorySessionLifecycleStore,
	createInMemoryUserSessionStore,
	createMemoryDeviceCodeStore,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import {
	coreConfigForTests,
	createTestCsrfGuard,
	createTestOAuthTokenSettings,
	makeValidCoreConfig,
	type OutboundSectionForTests,
	withOutbound,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { deviceAuthorizationGrantModule } from "#/module.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";
import { shippedDeviceGrantSection } from "./shippedSection.mjs";

const ISSUER = "https://as.example.test";
const CLIENT_ID = "assertion-app";
const INLINE_CLIENT = "inline-app";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

let privateKey: CryptoKey;
let stranger: CryptoKey;
let publicJwk: JWK;
let peer: Server;
let jwksUri: string;
const hits: string[] = [];
const disposals: (() => Promise<void>)[] = [];

beforeAll(async () => {
	const pair = await generateKeyPair("ES256");
	privateKey = pair.privateKey;
	publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1" };
	stranger = (await generateKeyPair("ES256")).privateKey;
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

afterEach(async () => {
	hits.length = 0;
	reasons.length = 0;
	vi.unstubAllEnvs();
	for (const dispose of disposals.splice(0)) await dispose();
});

const registered = (clientId: string, keys: object) => ({
	clientId,
	tokenEndpointAuthMethod: "private_key_jwt",
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
	...keys,
});

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

/** A composition with the grant on and `core.outbound` as `outbound` states it (absent: unwritten). */
const bootstrap = (outbound?: OutboundSectionForTests): BootstrapMap => {
	const core = makeValidCoreConfig();
	const config = {
		...core,
		...coreConfigForTests({ declaredAbsent: ["auditSink", "rateLimiter"] }),
		"device-grant": shippedDeviceGrantSection({
			enabled: true,
			verificationUri: "https://example.test/device",
		}),
	};
	return {
		config: outbound === undefined ? config : withOutbound(config, outbound),
		pathResolver: (s: string) => s,
		oauthTokenSettings: createTestOAuthTokenSettings({ issuer: ISSUER }),
		clientRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!!"),
		deviceCodeStore: createMemoryDeviceCodeStore(),
		userSessionStore: createInMemoryUserSessionStore(),
		// Core's session lifecycle port, required beside the user-session store.
		sessionLifecycleStore: createInMemorySessionLifecycleStore(),
		csrfGuard: createTestCsrfGuard(),
		replaySeenSet: createMemoryReplaySeenSet(),
		logger,
	} as unknown as BootstrapMap;
};

/** The device authorization route, mounted as boot mounts it. */
const mount = async (outbound?: OutboundSectionForTests): Promise<express.Express> => {
	const handle = await createApp({
		modules: [deviceAuthorizationGrantModule],
		bootstrapComponents: bootstrap(outbound),
	});
	disposals.push(() => handle.dispose());
	const app = express();
	app.use(handle.router);
	return app;
};

const authorize = async (
	app: express.Express,
	clientId = CLIENT_ID,
	key: CryptoKey = privateKey,
) => {
	const now = Math.floor(Date.now() / 1000);
	const assertion = await new SignJWT({
		iss: clientId,
		sub: clientId,
		aud: `${ISSUER}/oauth/token`,
		iat: now,
		exp: now + 60,
		jti: randomUUID(),
	})
		.setProtectedHeader({ alg: "ES256", kid: "k1" })
		.sign(key);
	return request(app)
		.post("/oauth/device_authorization")
		.type("form")
		.send({ client_assertion_type: ASSERTION_TYPE, client_assertion: assertion });
};

/** What a client is shown: the status, the body's bytes and the headers that describe it. */
const shown = (res: request.Response) => ({
	status: res.status,
	text: res.text,
	contentType: res.headers["content-type"],
	wwwAuthenticate: res.headers["www-authenticate"],
});

describe("device authorization — a client's jwksUri and core.outbound", () => {
	it("authenticates against a key set at a loopback host core.outbound.internalHosts lists", async () => {
		const res = await authorize(await mount({ internalHosts: ["127.0.0.1"] }));
		expect(res.status).toBe(200);
		expect(hits).toEqual(["/jwks"]);
	});

	it("refuses the same key set without the listing with the bytes a bad signature gets, and never asks it", async () => {
		const app = await mount();
		const refused = await authorize(app);
		const badSignature = await authorize(app, INLINE_CLIENT, stranger);
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
	});

	it("lets core.outbound.deniedHosts win over internalHosts", async () => {
		const res = await authorize(
			await mount({ internalHosts: ["127.0.0.1"], deniedHosts: ["127.0.0.1"] }),
		);
		expect(res.status).toBe(401);
		expect(reasons).toEqual(["jwks_uri_refused"]);
		expect(hits).toEqual([]);
	});

	it("refuses to boot over a malformed core.outbound", async () => {
		await expect(mount({ allowedHosts: ["not a host"] })).rejects.toThrow(
			/core\.outbound\.allowedHosts/,
		);
	});

	it("refuses to boot over an egress proxy core.outbound does not state as direct", async () => {
		vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:3128");
		await expect(mount()).rejects.toThrow(/core\.outbound\.egress/);
		await expect(mount({ egress: "direct" })).resolves.toBeDefined();
	});
});
