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
 * `jwksUri` through core's outbound fetch, built from the composition's
 * `core.outbound` when the route is.
 */

import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
	type AppConfig,
	type ClientRepository,
	createMemoryDeviceCodeStore,
	createMemoryRateLimiter,
	createMemoryReplaySeenSet,
} from "@o3co/auth-provider-core";
import { type OutboundSectionForTests, withOutbound } from "@o3co/auth-provider-core/testing";
import express from "express";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { deviceGrantConfigSchema, deviceGrantModule } from "#/module.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";

const ISSUER = "https://as.example.test";
const CLIENT_ID = "assertion-app";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

let privateKey: CryptoKey;
let publicJwk: JWK;
let peer: Server;
let jwksUri: string;
const hits: string[] = [];

beforeAll(async () => {
	const pair = await generateKeyPair("ES256");
	privateKey = pair.privateKey;
	publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1" };
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
	vi.unstubAllEnvs();
});

const baseConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 300 },
		refreshToken: { expiresIn: 86_400 },
	},
	"device-grant": {
		enabled: true,
		verificationUri: "https://example.test/device",
		verificationUriComplete: false,
		codeLifetimeSeconds: 600,
		pollingIntervalSeconds: 5,
		rateLimit: { limit: 5, windowSeconds: 300 },
	},
};

const clientRepository: ClientRepository = {
	findById: async (id) =>
		id === CLIENT_ID
			? ({
					clientId: CLIENT_ID,
					tokenEndpointAuthMethod: "private_key_jwt",
					allowedScopes: ["openid"],
					defaultScopes: ["openid"],
					allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
					jwksUri,
				} as never)
			: null,
	authenticate: async () => null,
};

/** The mounted device authorization route, built as boot builds it. */
const mount = (outbound?: OutboundSectionForTests): express.Express => {
	const config = outbound === undefined ? baseConfig : withOutbound(baseConfig, outbound);
	const route = deviceGrantModule({ config: config as unknown as AppConfig }).contributes
		?.routes?.[0] as (d: unknown) => { mountPath: string; handler: express.RequestHandler };
	const built = route({
		config,
		section: deviceGrantConfigSchema.parse(config["device-grant"]),
		clientRepository,
		deviceCodeStore: createMemoryDeviceCodeStore(),
		replaySeenSet: createMemoryReplaySeenSet(),
		rateLimiter: createMemoryRateLimiter({
			limits: { device_verification: { limit: 50, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		}),
	});
	const app = express();
	app.use(built.mountPath, built.handler);
	return app;
};

const authorize = async (app: express.Express) => {
	const now = Math.floor(Date.now() / 1000);
	const assertion = await new SignJWT({
		iss: CLIENT_ID,
		sub: CLIENT_ID,
		aud: `${ISSUER}/oauth/token`,
		iat: now,
		exp: now + 60,
		jti: randomUUID(),
	})
		.setProtectedHeader({ alg: "ES256", kid: "k1" })
		.sign(privateKey);
	return request(app)
		.post("/oauth/device_authorization")
		.type("form")
		.send({ client_assertion_type: ASSERTION_TYPE, client_assertion: assertion });
};

describe("device authorization — a client's jwksUri and core.outbound", () => {
	it("authenticates against a key set at a loopback host core.outbound.internalHosts lists", async () => {
		const res = await authorize(mount({ internalHosts: ["127.0.0.1"] }));
		expect(res.status).toBe(200);
		expect(hits).toEqual(["/jwks"]);
	});

	it("refuses the same key set without the listing, and never asks it", async () => {
		const res = await authorize(mount());
		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			error: "invalid_client",
			error_description: "Invalid client assertion",
		});
		expect(hits).toEqual([]);
	});

	it("lets core.outbound.deniedHosts win over internalHosts", async () => {
		const res = await authorize(
			mount({ internalHosts: ["127.0.0.1"], deniedHosts: ["127.0.0.1"] }),
		);
		expect(res.status).toBe(401);
		expect(hits).toEqual([]);
	});

	it("refuses to build the route over a malformed core.outbound", () => {
		expect(() => mount({ allowedHosts: ["not a host"] })).toThrow(/core\.outbound\.allowedHosts/);
	});

	it("refuses to build the route over an egress proxy core.outbound does not state as direct", () => {
		vi.stubEnv("HTTPS_PROXY", "http://proxy.example.test:3128");
		expect(() => mount()).toThrow(/core\.outbound\.egress/);
		expect(() => mount({ egress: "direct" })).not.toThrow();
	});
});
