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
 * A revocation is remembered for as long as a token it revoked is still
 * accepted.
 *
 * A refresh-token family's record expires with the family — the refresh
 * token's lifetime, set once at creation — and revocation used to keep that
 * expiry. An access token minted by a refresh late in the family's life
 * outlives it by up to its own lifetime, and the verifier accepts a token for
 * five minutes past its `exp` besides. Once the revoked record was gone,
 * `isFamilyRevoked` answered "no" and the token was served at userinfo and
 * reported active at introspection again. A family whose record had already
 * run out when it was revoked recorded nothing at all. The access-token
 * denylist had the same hole by five minutes: an entry kept until `exp` for
 * a token accepted until `exp` + the clock tolerance.
 *
 * Driven through the real router, the real refresh grant and core's real
 * family modules booted by `createTestApp` — the memory store, the default
 * rotation and revocation, as a composition wires them — with the clock
 * moved by `vi.setSystemTime`.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createMemoryAccessTokenDenylist,
	createSymmetricKeyStore,
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
	defineModule,
	memoryRefreshTokenFamilyStoreModule,
	type RefreshTokenFamilyRevocation,
	type RefreshTokenFamilyRotation,
} from "@o3co/auth-provider-core";
import { createTestApp, GrantRegistry, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";

const ISSUER = "https://auth.test";
const CLIENT_ID = "rp";
const CLIENT_SECRET = "rp-secret";
const FAMILY = "fam-1";
const HOUR = 3_600_000;

const base = makeValidAppConfig();
/** One-hour access tokens, one-day refresh families: the shipped defaults. */
const config = {
	...base,
	oauth: {
		...base.oauth,
		jwt: { ...base.oauth.jwt, issuer: ISSUER },
		accessToken: { defaultExpiresIn: 3600, maxExpiresIn: 3600 },
		refreshToken: { ...base.oauth.refreshToken, expiresIn: 86400 },
	},
	rateLimit: { ...base.rateLimit, failMode: "open" as const },
} as unknown as AppConfig;

const clientRecord = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: [],
	allowedScopes: ["openid"],
	allowedGrantTypes: ["refresh_token"],
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? clientRecord : null),
	authenticate: async (id, secret) =>
		id === CLIENT_ID && secret === CLIENT_SECRET ? clientRecord : null,
};

const codeRepository: CodeRepository = {
	createCode: async () => codeRecord({ code: "unused", client_id: CLIENT_ID, redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

/** Makes the planner build the family wrappers, as a module that requires them would. */
const familyConsumer = defineModule({
	name: "test:family-consumer",
	requires: ["refreshTokenFamilyRotation", "refreshTokenFamilyRevocation"] as const,
	contributes: {
		routes: [
			{
				mountPath: "/__test_noop__",
				id: "test-noop",
				handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
			},
		],
	},
});

interface Harness {
	readonly app: express.Express;
	readonly rotation: RefreshTokenFamilyRotation;
	readonly mintRefreshToken: (jti: string, expSeconds: number) => Promise<string>;
}

async function buildApp(): Promise<Harness> {
	const handle = await createTestApp({
		modules: [
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRotationModule,
			defaultRefreshTokenFamilyRevocationModule,
			familyConsumer,
		],
		bootstrapComponents: { config, pathResolver: (s: string) => s } as never,
	});
	const rotation = handle.components.refreshTokenFamilyRotation as RefreshTokenFamilyRotation;
	const revocation = handle.components.refreshTokenFamilyRevocation as RefreshTokenFamilyRevocation;
	const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!", "v0");
	const registry = new GrantRegistry();
	registry.register(
		"refresh_token",
		createRefreshTokenGrant({
			config,
			keyStore,
			refreshTokenFamilyRotation: rotation,
			refreshTokenFamilyRevocation: revocation,
		}),
	);
	const { router } = await createOAuthRouter(express, {
		registry,
		config,
		clientRepository,
		codeRepository,
		keyStore,
		refreshTokenFamilyRevocation: revocation,
		accessTokenDenylist: createMemoryAccessTokenDenylist(),
	});
	const app = express();
	app.use("/oauth", router);
	const mintRefreshToken = (jti: string, expSeconds: number) =>
		keyStore.sign({
			claims: {
				iss: ISSUER,
				sub: "user-1",
				aud: CLIENT_ID,
				azp: CLIENT_ID,
				scope: "openid",
				family_id: FAMILY,
				jti,
				iat: Math.floor(Date.now() / 1000),
				exp: expSeconds,
			},
			header: { typ: "rt+jwt" },
		});
	return { app, rotation, mintRefreshToken };
}

const refresh = async (app: express.Express, refreshToken: string) => {
	const res = await request(app)
		.post("/oauth/token")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ grant_type: "refresh_token", refresh_token: refreshToken });
	expect(res.status, JSON.stringify(res.body)).toBe(200);
	return res.body as { access_token: string; refresh_token: string };
};
const revoke = (app: express.Express, token: string, hint: "refresh_token" | "access_token") =>
	request(app)
		.post("/oauth/revoke")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ token, token_type_hint: hint });
const userinfo = (app: express.Express, accessToken: string) =>
	request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${accessToken}`);
const introspect = (app: express.Express, accessToken: string) =>
	request(app)
		.post("/oauth/introspect")
		.auth(CLIENT_ID, CLIENT_SECRET)
		.type("form")
		.send({ token: accessToken });

/** The clock, moved forward by `ms`. */
const advance = (ms: number): void => {
	vi.setSystemTime(Date.now() + ms);
};

/**
 * A family created now, then refreshed ten minutes before its one-day
 * lifetime runs out: the access token that refresh mints lives fifty minutes
 * past the family's own record.
 */
async function lateAccessToken(h: Harness) {
	const createdAt = Date.now();
	const familyEndsSeconds = Math.floor((createdAt + 24 * HOUR) / 1000);
	await h.rotation.register("rt-0", FAMILY, familyEndsSeconds * 1000);
	const first = await h.mintRefreshToken("rt-0", familyEndsSeconds);
	advance(24 * HOUR - 10 * 60_000);
	return refresh(h.app, first);
}

describe("a revoked refresh-token family is remembered while its access tokens are accepted", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("keeps refusing the access token after the family's own lifetime has run out", async () => {
		const h = await buildApp();
		const tokens = await lateAccessToken(h);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(200);

		advance(5 * 60_000);
		expect((await revoke(h.app, tokens.refresh_token, "refresh_token")).status).toBe(200);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(401);

		// Past the family's own expiry — how long a revoked record used to be
		// kept — with the access token still forty minutes from its exp.
		advance(10 * 60_000);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(401);
		expect((await introspect(h.app, tokens.access_token)).body).toEqual({ active: false });

		// And past the access token's exp plus the verifier's five-minute
		// tolerance, where nothing is accepted any more, by signature alone.
		advance(45 * 60_000);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(401);
	});

	it("records a revocation that arrives after the family's own record ran out", async () => {
		const h = await buildApp();
		const tokens = await lateAccessToken(h);

		// The family's record expires; its last access token has not.
		advance(15 * 60_000);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(200);

		// The refresh token is past its exp too — RFC 7009 still lets it be
		// revoked, and revoking it must reach the family's access tokens.
		expect((await revoke(h.app, tokens.refresh_token, "refresh_token")).status).toBe(200);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(401);
		expect((await introspect(h.app, tokens.access_token)).body).toEqual({ active: false });
	});
});

describe("a revoked access token is remembered while the verifier still accepts it", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("keeps refusing it through the clock tolerance past its exp", async () => {
		const h = await buildApp();
		const tokens = await lateAccessToken(h);
		expect((await revoke(h.app, tokens.access_token, "access_token")).status).toBe(200);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(401);

		// One minute past `exp`: inside the verifier's five-minute tolerance,
		// so only the denylist stands between the token and the claims.
		advance(61 * 60_000);
		expect((await userinfo(h.app, tokens.access_token)).status).toBe(401);
		expect((await introspect(h.app, tokens.access_token)).body).toEqual({ active: false });
	});
});
