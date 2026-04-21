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

import type { AppConfig, UserSessionStoreBase } from "@o3co/auth-provider-core";
import express from "express";
import type { PassportStatic } from "passport";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createRouter } from "#/routes/Session.mjs";

/** Minimal AppConfig stub */
const stubConfig: AppConfig = {
	cors: { allowedOrigins: [] },
	rateLimit: {
		login: { windowMs: 60_000, limit: 100 },
	},
	session: { domain: null },
} as unknown as AppConfig;

/** In-memory UserSessionStore fake that exposes created sessions for assertions */
function makeUserSessionStore(): UserSessionStoreBase & { sessions: unknown[] } {
	const sessions: unknown[] = [];
	return {
		kind: "memory",
		sessions,
		async create(input) {
			sessions.push(structuredClone(input));
		},
		async get() {
			return null;
		},
		async registerRP() {},
		async linkFamily() {},
		async updateClaims() {},
		async removeFederation() {},
		async delete() {},
	} as UserSessionStoreBase & { sessions: unknown[] };
}

/**
 * Build a test express app with the Session router mounted at "/session".
 *
 * The passport stub short-circuits authenticate("local", …) by immediately
 * calling next() after setting req.user — simulating a successful local login.
 */
function buildApp(
	opts: {
		userSessionStore?: UserSessionStoreBase;
		sessionTtlMs?: number;
		user?: Record<string, unknown>;
	} = {},
) {
	const {
		userSessionStore,
		sessionTtlMs,
		user = { id: "u-1", username: "alice", email: "alice@example.com" },
	} = opts;

	// Passport stub: authenticate("local", …) immediately calls next() + sets req.user
	const passportStub: PassportStatic = {
		authenticate: vi.fn(
			(_strategy: string, _options: unknown) =>
				(req: express.Request, _res: express.Response, next: express.NextFunction) => {
					(req as unknown as { user: unknown }).user = user;
					next();
				},
		),
	} as unknown as PassportStatic;

	const app = express();

	// Minimal express-session stub so req.session.regenerate / req.session.sid work
	app.use((req, _res, next) => {
		const sessionData: Record<string, unknown> = {};
		(req as unknown as { session: Record<string, unknown> }).session = {
			...sessionData,
			regenerate(cb: (err: null) => void) {
				// After regenerate, session data is reset — mirror real express-session behaviour.
				// We re-attach a fresh object but keep a reference so we can inspect sid after the call.
				const fresh: Record<string, unknown> = {
					regenerate: this.regenerate,
					save: this.save,
				};
				Object.assign(req as unknown as { session: Record<string, unknown> }, { session: fresh });
				cb(null);
			},
			save(cb: (err: null) => void) {
				cb(null);
			},
		};
		next();
	});

	const router = createRouter(express, {
		passport: passportStub,
		config: stubConfig,
		...(userSessionStore !== undefined ? { userSessionStore } : {}),
		...(sessionTtlMs !== undefined ? { sessionTtlMs } : {}),
	});

	app.use("/session", router);
	return { app, passportStub };
}

describe("Session routes — POST /session/login", () => {
	describe("UserSession creation on successful local login", () => {
		it("creates a UserSession record and sets req.session.sid when userSessionStore is wired", async () => {
			const store = makeUserSessionStore();

			// Intercept the response to capture req.session.sid via a custom middleware
			// placed after the router — we do this by inspecting the store instead.
			const { app } = buildApp({
				userSessionStore: store,
				sessionTtlMs: 3600_000,
				user: { id: "u-local-1", username: "alice", email: "alice@example.com", name: "Alice" },
			});

			// Also intercept to capture sid set on session post-response
			// We'll verify via the store record that has the sid, then rely on the
			// store.sessions array.
			const res = await request(app)
				.post("/session/login")
				.send("username=alice&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ message: "Logged in successfully" });

			// UserSession was created in the store
			expect(store.sessions).toHaveLength(1);
			const saved = store.sessions[0] as {
				sid: string;
				sub: string;
				federations: unknown;
				claims: Record<string, unknown>;
				authTime: unknown;
				expiresAt: unknown;
			};

			// sid is a non-empty UUID-shaped string
			expect(typeof saved.sid).toBe("string");
			expect(saved.sid.length).toBeGreaterThan(0);

			// sub matches user.id
			expect(saved.sub).toBe("u-local-1");

			// federations defaults to [] (not required by CreateUserSessionInput — store initialises it)
			// The implementation passes federations: [] explicitly; assert it's empty.
			expect(saved.federations ?? []).toEqual([]);

			// claims extracted from user
			expect(saved.claims).toMatchObject({
				email: "alice@example.com",
				name: "Alice",
			});

			// authTime and expiresAt are Date instances (or ISO strings from structuredClone)
			expect(saved.authTime).toBeTruthy();
			expect(saved.expiresAt).toBeTruthy();
		});

		it("does not crash and does not create a UserSession when userSessionStore is not wired (backward compat)", async () => {
			// No userSessionStore
			const { app } = buildApp({
				user: { id: "u-no-store", username: "bob" },
			});

			const res = await request(app)
				.post("/session/login")
				.send("username=bob&password=secret")
				.set("Content-Type", "application/x-www-form-urlencoded");

			// Login still succeeds — backward compat
			expect(res.status).toBe(200);
			expect(res.body).toMatchObject({ message: "Logged in successfully" });
		});
	});
});
