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
 * R3 — `/oauth/introspect` consults session liveness for a `sid`-carrying
 * token.
 *
 * The handler already consulted the jti denylist, the subject watermark and
 * the refresh-token family; the session was the missing leg. That gap is what
 * let a logged-out `session`-grant token keep reporting `active: true` while
 * `/oauth/userinfo` — which does run the check — refused the very same token.
 *
 * These pin the check's own shape: which tokens pay for it, what a store
 * outage answers, and what an operator sees.
 */

import { createSecretKey } from "node:crypto";
import {
	type AppConfig,
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const SID = "sid-live";

const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const config = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
		grants: {},
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const codeRepository: CodeRepository = {
	createCode: async () => ({ code: "c", client_id: "x", redirect_uri: "" }),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const liveSession: UserSession = {
	sid: SID,
	sub: "u1",
	authTime: new Date(),
	createdAt: new Date(),
	expiresAt: new Date(Date.now() + 3_600_000),
	claims: {},
};

async function mintAccessToken(extra: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read", ...extra })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setExpirationTime("1h")
		.setIssuedAt()
		.sign(secretKey);
}

async function buildApp(opts: { userSessionStore?: UserSessionStore; auditSink?: AuditSink }) {
	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config,
		clientRepository,
		codeRepository,
		keyStore,
		...(opts.userSessionStore ? { userSessionStore: opts.userSessionStore } : {}),
		...(opts.auditSink ? { auditSink: opts.auditSink } : {}),
	});
	app.use("/oauth", router);
	return app;
}

/** Bearer self-introspection: the caller presents the token as its own credential. */
const introspect = (app: express.Express, token: string) =>
	request(app)
		.post("/oauth/introspect")
		.set("Authorization", `Bearer ${token}`)
		.type("form")
		.send({ token });

describe("/oauth/introspect — session liveness (R3)", () => {
	it("reports active:true while the session named by sid is live", async () => {
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async () => liveSession),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const app = await buildApp({ userSessionStore: store });

		const res = await introspect(app, await mintAccessToken({ sid: SID }));

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(store.get).toHaveBeenCalledWith(SID);
	});

	it("reports active:false once the session is gone", async () => {
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async () => null),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const app = await buildApp({ userSessionStore: store });

		const res = await introspect(app, await mintAccessToken({ sid: SID }));

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("emits introspect.session_invalid so an operator can see why", async () => {
		const events: AuditEvent[] = [];
		const auditSink: AuditSink = {
			kind: "spy",
			record: async (e) => {
				events.push(e);
			},
		};
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async () => null),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const app = await buildApp({ userSessionStore: store, auditSink });

		await introspect(app, await mintAccessToken({ sid: SID }));
		await new Promise((r) => setImmediate(r));

		const event = events.find((e) => e.type === "introspect.session_invalid");
		expect(event).toBeDefined();
		expect(event?.details).toMatchObject({ sid: SID });
	});

	it("fails closed to active:false when the session store throws", async () => {
		// RFC 7662 defines no `temporarily_unavailable` for introspection, so
		// inactive is the only answer that keeps a resource server on the safe
		// side of its scope gate — the same rule the family check follows.
		const events: AuditEvent[] = [];
		const auditSink: AuditSink = {
			kind: "spy",
			record: async (e) => {
				events.push(e);
			},
		};
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async () => {
				throw new Error("redis down");
			}),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const app = await buildApp({ userSessionStore: store, auditSink });

		const res = await introspect(app, await mintAccessToken({ sid: SID }));
		await new Promise((r) => setImmediate(r));

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		expect(events.find((e) => e.type === "introspect.store_unavailable")).toBeDefined();
	});

	it("does not read the store for a token carrying no sid", async () => {
		// Client credentials, jwt-bearer, anything minted outside a browser
		// session: there is no session to check, so the check costs nothing.
		const store = {
			kind: "memory",
			create: vi.fn(async () => {}),
			get: vi.fn(async () => null),
			delete: vi.fn(async () => {}),
		} as unknown as UserSessionStore;
		const app = await buildApp({ userSessionStore: store });

		const res = await introspect(app, await mintAccessToken());

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(store.get).not.toHaveBeenCalled();
	});

	it("is inert when no session store is wired", async () => {
		const app = await buildApp({});

		const res = await introspect(app, await mintAccessToken({ sid: SID }));

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
	});
});
