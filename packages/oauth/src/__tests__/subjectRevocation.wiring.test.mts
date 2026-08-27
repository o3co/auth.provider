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
 * Issue #296 — the seam between writing the watermark and it meaning anything.
 *
 * `verifyJwt` honours a `subjectRevocation` when one is passed, and
 * `revokeAllForSubject` writes the watermark. Neither fact matters unless the
 * protected-resource surfaces actually pass the store, which is what this
 * pins: an option nothing forwards is a revocation that revokes nothing — the
 * same silent no-op #277 was filed about for the jti denylist.
 *
 * The surfaces are the ones that already consult `accessTokenDenylist`:
 * `/oauth/introspect` (both the body handler and the bearer-credential path),
 * `/oauth/userinfo`, and the federation-token route.
 */

import { createSecretKey } from "node:crypto";
import {
	type ClientRepository,
	type CodeRepository,
	createInMemorySubjectRevocation,
	createSymmetricKeyStore,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter as createUserinfoRouter } from "#/routes/userinfo.mjs";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const ISSUER = "https://auth.example";
const CLIENT_ID = "c-1";
const SUBJECT = "u-1";

const clientRepository: ClientRepository = {
	findById: async (id) =>
		id === CLIENT_ID
			? {
					clientId: id,
					tokenEndpointAuthMethod: "client_secret_basic",
					allowedRedirectUris: [],
					allowedScopes: [],
				}
			: null,
	authenticate: async () => null,
};

const codeRepository: CodeRepository = {
	createCode: async () => ({
		code: "test-code",
		client_id: CLIENT_ID,
		redirect_uri: "https://rp.example/cb",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const baseConfig = {
	...makeValidAppConfig(),
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	endpoints: { login: { url: "/login" } },
} as unknown as import("@o3co/auth-provider-core").AppConfig;

const nowSec = () => Math.floor(Date.now() / 1000);

/** Mint an otherwise-valid access token with an explicit `iat`. */
async function mintAT(opts: { iatSeconds: number; jti?: string; sid?: string }): Promise<string> {
	return new SignJWT({
		sub: SUBJECT,
		scope: "openid email",
		client_id: CLIENT_ID,
		...(opts.jti ? { jti: opts.jti } : {}),
		...(opts.sid ? { sid: opts.sid } : {}),
	})
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(CLIENT_ID)
		.setIssuedAt(opts.iatSeconds)
		.setExpirationTime(opts.iatSeconds + 3600)
		.sign(secretKey);
}

const session: UserSession = {
	sid: "sid-1",
	sub: SUBJECT,
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: { email: "alice@example.com", emailVerified: true },
};

describe("#296 — the subject watermark reaches /oauth/introspect", () => {
	const buildApp = async (
		subjectRevocation?: ReturnType<typeof createInMemorySubjectRevocation>,
	) => {
		const { router } = await createOAuthRouter(express, {
			registry: new GrantRegistry(),
			config: baseConfig,
			clientRepository,
			codeRepository,
			keyStore,
			...(subjectRevocation ? { subjectRevocation } : {}),
		});
		const app = express();
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		app.use("/oauth", router);
		return app;
	};

	it("reports a token minted before the watermark as active:false", async () => {
		const store = createInMemorySubjectRevocation();
		const app = await buildApp(store);
		const at = await mintAT({ iatSeconds: nowSec() - 60, jti: "j-1" });

		// Before the credential change the same token is live.
		const before = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${at}`)
			.type("form")
			.send({ token: at });
		expect(before.body.active).toBe(true);

		await store.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));

		const after = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${at}`)
			.type("form")
			.send({ token: at });
		expect(after.status).toBe(200);
		expect(after.body.active).toBe(false);
	});

	it("leaves a token minted after the watermark active", async () => {
		const store = createInMemorySubjectRevocation();
		const app = await buildApp(store);
		await store.revokeBefore(
			SUBJECT,
			new Date((nowSec() - 60) * 1000),
			new Date(Date.now() + 3_600_000),
		);
		const at = await mintAT({ iatSeconds: nowSec(), jti: "j-2" });

		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${at}`)
			.type("form")
			.send({ token: at });
		expect(res.body.active).toBe(true);
	});

	it("is inert when no subjectRevocation is wired", async () => {
		const app = await buildApp();
		const at = await mintAT({ iatSeconds: nowSec() - 60, jti: "j-3" });

		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", `Bearer ${at}`)
			.type("form")
			.send({ token: at });
		expect(res.body.active).toBe(true);
	});
});

describe("#296 — the subject watermark reaches /oauth/userinfo", () => {
	const buildApp = (subjectRevocation?: ReturnType<typeof createInMemorySubjectRevocation>) => {
		const app = express();
		app.use(express.json());
		app.use(
			"/oauth",
			createUserinfoRouter(express, {
				keyStore,
				issuer: ISSUER,
				userSessionStore: {
					kind: "memory",
					get: vi.fn().mockResolvedValue(session),
				} as unknown as UserSessionStore,
				...(subjectRevocation ? { subjectRevocation } : {}),
			}),
		);
		return app;
	};

	it("rejects a token minted before the watermark with 401", async () => {
		const store = createInMemorySubjectRevocation();
		const app = buildApp(store);
		const at = await mintAT({ iatSeconds: nowSec() - 60, sid: "sid-1" });

		const before = await request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${at}`);
		expect(before.status).toBe(200);

		await store.revokeBefore(SUBJECT, new Date(), new Date(Date.now() + 3_600_000));

		const after = await request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${at}`);
		expect(after.status).toBe(401);
	});

	it("serves a token minted after the watermark", async () => {
		const store = createInMemorySubjectRevocation();
		await store.revokeBefore(
			SUBJECT,
			new Date((nowSec() - 60) * 1000),
			new Date(Date.now() + 3_600_000),
		);
		const app = buildApp(store);
		const at = await mintAT({ iatSeconds: nowSec(), sid: "sid-1" });

		const res = await request(app).get("/oauth/userinfo").set("Authorization", `Bearer ${at}`);
		expect(res.status).toBe(200);
	});
});
