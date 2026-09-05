// SPDX-FileCopyrightText: 2026 1o1 Co. Ltd.
// SPDX-License-Identifier: Apache-2.0

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createInMemoryUserSessionStore,
	createSymmetricKeyStore,
	type GrantDependencies,
	type TokenBinding,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createSessionGrant } from "#/grants/session.mjs";
import { createOAuthRouter } from "#/routes.mjs";

const SID = "browser-session";
const SUB = "user-1";
const config = {
	oauth: {
		jwt: { issuer: "https://issuer.test" },
		accessToken: { expiresIn: 60 },
		refreshToken: { expiresIn: 86400 },
		grants: { session: { enabled: true } },
	},
	rateLimit: { failMode: "open" },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;
const keyStore = createSymmetricKeyStore("session-security-test-secret-32-bytes");
const codeRepository: CodeRepository = {
	createCode: async () => ({ code: "unused", client_id: "app", redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

async function liveStore() {
	const store = createInMemoryUserSessionStore();
	await store.create({
		sid: SID,
		sub: SUB,
		authTime: new Date(),
		expiresAt: new Date(Date.now() + 60_000),
		claims: {},
	});
	return store;
}

async function buildApp(
	store?: UserSessionStore,
	binding?: TokenBinding,
	sid: string | undefined = SID,
	browserUser: { id?: unknown } = { id: SUB },
) {
	const client = {
		clientId: "app",
		tokenEndpointAuthMethod: "none" as const,
		allowedRedirectUris: [],
		allowedScopes: ["read"],
		allowedGrantTypes: ["session"],
		...(binding ? { senderConstrained: { required: true, methods: [binding.kind] } } : {}),
	};
	const clientRepository: ClientRepository = {
		findById: async (id) => (id === "app" ? client : null),
		authenticate: async () => null,
	};
	const registry = new GrantRegistry();
	registry.register(
		"session",
		createSessionGrant({
			config,
			keyStore,
			userSessionStore: store,
		} as GrantDependencies),
	);
	const { router } = await createOAuthRouter(express, {
		registry,
		config,
		keyStore,
		codeRepository,
		clientRepository,
		userSessionStore: store,
	});
	const app = express();
	app.use((req, _res, next) => {
		// A persisted express-session survives an independent UserSession revocation.
		req.session = { isAuthenticated: true, user: browserUser, sid } as typeof req.session;
		// The binding middleware has already validated this evidence. These tests
		// exercise dispatch and issuance, not proof parsing or TLS termination.
		if (binding) req.tokenBinding = binding;
		next();
	});
	app.use("/oauth", router);
	return app;
}

const mint = (app: express.Express) =>
	request(app)
		.post("/oauth/token")
		.type("form")
		.send({ grant_type: "session", client_id: "app", scope: "read" });

describe("session grant authentication and token binding", () => {
	it.each([{ id: "another-user" }, {}, { id: null }])(
		"refuses a browser identity that does not match the tracked subject: %j",
		async (browserUser) => {
			const result = await mint(await buildApp(await liveStore(), undefined, SID, browserUser));
			expect(result.status).toBe(400);
			expect(result.body.error).toBe("invalid_grant");
			expect(result.body.access_token).toBeUndefined();
		},
	);

	it.each([undefined, null, "", 42])("refuses an invalid tracked subject: %j", async (sub) => {
		const store = await liveStore();
		const record = await store.get(SID);
		if (!record) throw new Error("test session was not created");
		vi.spyOn(store, "get").mockResolvedValue({ ...record, sub: sub as string });
		const result = await mint(await buildApp(store));
		expect(result.status).toBe(400);
		expect(result.body.error).toBe("invalid_grant");
		expect(result.body.access_token).toBeUndefined();
	});

	it("issues the tracked subject when browser and store identities agree", async () => {
		const result = await mint(await buildApp(await liveStore()));
		expect(result.status).toBe(200);
		expect(decodeJwt(result.body.access_token).sub).toBe(SUB);
	});

	it("refuses fresh issuance after UserSession revocation with the browser session retained", async () => {
		const store = await liveStore();
		const app = await buildApp(store);
		expect((await mint(app)).status).toBe(200);
		await store.delete(SID);
		const after = await mint(app);
		expect(after.status).toBe(400);
		expect(after.body.error).toBe("invalid_grant");
		expect(after.body.access_token).toBeUndefined();
	});

	it("refuses an expired UserSession", async () => {
		const store = await liveStore();
		const app = await buildApp(store);
		const realNow = Date.now();
		const clock = vi.spyOn(Date, "now").mockReturnValue(realNow + 120_000);
		try {
			const result = await mint(app);
			expect(result.status).toBe(400);
			expect(result.body.access_token).toBeUndefined();
		} finally {
			clock.mockRestore();
		}
	});

	it("fails closed on a UserSession store outage", async () => {
		const store = await liveStore();
		store.get = async () => {
			throw new Error("store unavailable");
		};
		const result = await mint(await buildApp(store));
		expect(result.status).toBe(503);
		expect(result.body.error).toBe("temporarily_unavailable");
		expect(result.body.access_token).toBeUndefined();
	});

	it("requires a sid when a session store is configured", async () => {
		const result = await mint(await buildApp(await liveStore(), undefined, ""));
		expect(result.status).toBe(400);
		expect(result.body.access_token).toBeUndefined();
	});

	it("preserves untracked deployments without a session store", async () => {
		const result = await mint(await buildApp(undefined, undefined, ""));
		expect(result.status).toBe(200);
		expect(result.body.token_type).toBe("Bearer");
	});

	it.each([
		{ kind: "dpop", confirmation: { jkt: "proof-key" } },
		{ kind: "mtls", confirmation: { "x5t#S256": "certificate" } },
	] satisfies TokenBinding[])(
		"retains the $kind binding after authenticated grant dispatch",
		async (binding) => {
			const result = await mint(await buildApp(await liveStore(), binding));
			expect(result.status).toBe(200);
			expect(decodeJwt(result.body.access_token).cnf).toEqual(binding.confirmation);
			expect(result.body.token_type).toBe(binding.kind === "dpop" ? "DPoP" : "Bearer");
		},
	);
});
