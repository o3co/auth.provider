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

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type AuditSinkBase,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	GrantRegistry,
	type ModuleContext,
	type RefreshTokenStoreBase,
} from "@o3co/auth-provider-core";
import type { Router } from "express";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthModule } from "#/module.mjs";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const mockConfig = {
	oauth: {
		jwt: { issuer: "https://auth.example" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

const mockClientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const mockCodeRepository: CodeRepository = {
	createCode: async () => ({ code: "test-code" }),
	getByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

async function makeAccessToken(overrides: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read", ...overrides })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setExpirationTime("1h")
		.sign(secretKey);
}

async function buildApp(refreshTokenStore?: RefreshTokenStoreBase, auditSink?: AuditSinkBase) {
	const app = express();
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: mockConfig,
		clientRepository: mockClientRepository,
		codeRepository: mockCodeRepository,
		keyStore,
		refreshTokenStore,
		auditSink,
	});

	app.use("/oauth", router);
	return app;
}

// Use the Bearer self-introspection path: Bearer token == body token.
// RFC 7662 §2.1 allows the resource server (or the client itself) to send
// the same token as the Bearer credential — the introspect handler validates
// that the body.token matches the Authorization header token, then proceeds.
async function introspect(app: ReturnType<typeof express>, token: string) {
	return request(app)
		.post("/oauth/introspect")
		.set("Authorization", `Bearer ${token}`)
		.send({ token });
}

describe("/introspect — family revoke cascade (TODO-F-3 task 5)", () => {
	it("returns active:true when family_id present and isFamilyRevoked returns false", async () => {
		const familyId = "fam-abc";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(false),
		};

		const app = await buildApp(refreshTokenStore);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(refreshTokenStore.isFamilyRevoked).toHaveBeenCalledWith(familyId);
	});

	it("returns active:false when family_id present and isFamilyRevoked returns true", async () => {
		const familyId = "fam-revoked";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		};

		const app = await buildApp(refreshTokenStore);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("returns active:false (fail-closed) when isFamilyRevoked throws", async () => {
		const familyId = "fam-error";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockRejectedValue(new Error("store unavailable")),
		};

		const app = await buildApp(refreshTokenStore);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("emits introspect.store_unavailable audit event when isFamilyRevoked throws", async () => {
		const familyId = "fam-error-audit";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockRejectedValue(new Error("backend down")),
		};
		const events: AuditEvent[] = [];
		const auditSink: AuditSinkBase = {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		};

		const app = await buildApp(refreshTokenStore, auditSink);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		const storeEvent = events.find((e) => e.type === "introspect.store_unavailable");
		expect(storeEvent).toBeDefined();
		expect((storeEvent?.details as Record<string, unknown>)?.family_id).toBe(familyId);
		expect((storeEvent?.details as Record<string, unknown>)?.error).toContain("backend down");
	});

	it("emits introspect.family_revoked audit event when family is revoked", async () => {
		const familyId = "fam-revoked-audit";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		};
		const events: AuditEvent[] = [];
		const auditSink: AuditSinkBase = {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		};

		const app = await buildApp(refreshTokenStore, auditSink);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		const revokedEvent = events.find((e) => e.type === "introspect.family_revoked");
		expect(revokedEvent).toBeDefined();
		expect((revokedEvent?.details as Record<string, unknown>)?.family_id).toBe(familyId);
	});

	it("returns active:true and does NOT consult store for legacy token without family_id", async () => {
		const token = await makeAccessToken(); // no family_id claim

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			// Throws if called — ensures no consultation for legacy tokens
			isFamilyRevoked: vi.fn().mockImplementation(() => {
				throw new Error("isFamilyRevoked must not be called for legacy tokens");
			}),
		};

		const app = await buildApp(refreshTokenStore);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(refreshTokenStore.isFamilyRevoked).not.toHaveBeenCalled();
	});

	it("rejects empty-string family_id and does NOT consult store", async () => {
		// family_id: "" should be treated as missing (M1 guard)
		const token = await makeAccessToken({ family_id: "" });

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockImplementation(() => {
				throw new Error("isFamilyRevoked must not be called for empty family_id");
			}),
		};

		const app = await buildApp(refreshTokenStore);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(refreshTokenStore.isFamilyRevoked).not.toHaveBeenCalled();
	});
});

describe("oauthModule.init — refreshTokenStore composition (C1)", () => {
	it("threads refreshTokenStore through to /introspect so family revocation returns active:false", async () => {
		// This test proves C1 is fixed at the module layer: oauthModule.init must
		// pass context.refreshTokenStore into createOAuthRouter. A revoked family
		// must yield active:false even when the app is wired via oauthModule.
		const app = express();
		app.set("trust proxy", 1);
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));

		const familyId = "fam-module-revoked";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenStore: RefreshTokenStoreBase = {
			kind: "test",
			rotate: vi.fn(),
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		};

		const rootRouter = express.Router() as Router;
		const ctx: ModuleContext = {
			pathResolver: (s: string) => s,
			config: mockConfig,
			keyStore,
			grantRegistry: new GrantRegistry(),
			router: rootRouter,
			refreshTokenStore,
		};

		const module = oauthModule({
			clientRepository: mockClientRepository,
			codeRepository: mockCodeRepository,
			express,
		});

		await module.init(ctx);
		app.use(rootRouter);

		const res = await introspect(app, token);

		// If C1 is fixed, the store was consulted and the family is revoked → inactive.
		// If C1 were broken (store not threaded), isFamilyRevoked would not be called
		// and the token would appear active:true.
		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		expect(refreshTokenStore.isFamilyRevoked).toHaveBeenCalledWith(familyId);
	});
});
