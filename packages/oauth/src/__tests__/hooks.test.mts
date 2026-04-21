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

import {
	type AppConfig,
	type AuditEvent,
	type AuditSinkBase,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	GrantRegistry,
	type RateLimiterBase,
} from "@o3co/auth-provider-core";
import express from "express";
import type { PassportStatic } from "passport";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const mockConfig = {
	oauth: {
		jwt: { issuer: "https://auth.example" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as AppConfig;

const mockPassport = {
	authenticate: () => (_req: unknown, _res: unknown, next: () => void) => next(),
} as unknown as PassportStatic;

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

function createStubRateLimiter(
	onCheck: (key: string) => { allowed: boolean; reason?: string; resetAt?: Date },
): RateLimiterBase {
	return {
		kind: "stub",
		async check(key) {
			return onCheck(key);
		},
	};
}

function createSpyAuditSink(): { sink: AuditSinkBase; events: AuditEvent[] } {
	const events: AuditEvent[] = [];
	return {
		events,
		sink: {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		},
	};
}

async function buildApp(overrides: { rateLimiter?: RateLimiterBase; auditSink?: AuditSinkBase }) {
	const app = express();
	// Required so express-rate-limit can resolve req.ip in test environment
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));

	const { router } = await createOAuthRouter(express, {
		passport: mockPassport,
		registry: new GrantRegistry(),
		config: mockConfig,
		clientRepository: mockClientRepository,
		codeRepository: mockCodeRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!"),
		...overrides,
	});

	app.use("/oauth", router);
	return app;
}

describe("oauth routes — TODO-C hooks (Phase 1)", () => {
	describe("rateLimiter hook", () => {
		it("returns 429 rate_limited when rateLimiter denies /oauth/token", async () => {
			const app = await buildApp({
				rateLimiter: createStubRateLimiter(() => ({
					allowed: false,
					reason: "limit:token",
					resetAt: new Date(Date.now() + 30_000),
				})),
			});

			const res = await request(app).post("/oauth/token").send({ grant_type: "password" });

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
			expect(res.body.reason).toBe("limit:token");
			const retryAfter = Number(res.headers["retry-after"]);
			expect(retryAfter).toBeGreaterThanOrEqual(29);
		});

		it("sets Retry-After header from decision.resetAt", async () => {
			const resetAt = new Date(Date.now() + 60_000);
			const app = await buildApp({
				rateLimiter: createStubRateLimiter(() => ({
					allowed: false,
					reason: "limit:token",
					resetAt,
				})),
			});

			const res = await request(app).post("/oauth/token").send({ grant_type: "refresh_token" });

			expect(res.status).toBe(429);
			expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
		});

		it("returns 429 rate_limited when rateLimiter denies /oauth/introspect", async () => {
			const app = await buildApp({
				rateLimiter: createStubRateLimiter((key) =>
					key.startsWith("introspect")
						? { allowed: false, reason: "limit:introspect" }
						: { allowed: true },
				),
			});

			const res = await request(app).post("/oauth/introspect").send({ token: "any" });

			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
		});

		it("does not block requests when rateLimiter allows", async () => {
			const app = await buildApp({
				rateLimiter: createStubRateLimiter(() => ({ allowed: true })),
			});

			const res = await request(app)
				.post("/oauth/token")
				.send({ grant_type: "unsupported_type_xyz" });

			// Not 429 — rate limiter allowed; 400 from unsupported_grant_type
			expect(res.status).toBe(400);
			expect(res.body.error).toBe("unsupported_grant_type");
		});
	});

	describe("auditSink hook", () => {
		it("emits token.issued.failure audit event for unsupported grant_type", async () => {
			const { sink, events } = createSpyAuditSink();
			const app = await buildApp({ auditSink: sink });

			await request(app).post("/oauth/token").send({ grant_type: "unsupported_xyz" });

			expect(events.length).toBeGreaterThanOrEqual(1);
			const ev = events.find((e) => e.type === "token.issued.failure");
			expect(ev).toBeDefined();
		});

		it("does not throw when auditSink is undefined (no-op)", async () => {
			const app = await buildApp({});

			const res = await request(app).post("/oauth/token").send({ grant_type: "unsupported_xyz" });

			expect(res.status).toBe(400);
		});
	});
});
