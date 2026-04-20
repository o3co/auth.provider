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

import type { AppConfig } from "@o3co/auth-provider-core";
import express from "express";
import type { PassportStatic } from "passport";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FederationProviderBase } from "#/federations/types.mjs";
import { createRouter } from "#/routes/Federation.mjs";

/** Minimal mock for a FederationProviderBase */
function makeMockProvider(name: string, scope: string[]): FederationProviderBase {
	return {
		name,
		scope,
		validateRedirect: vi.fn().mockReturnValue({ ok: true, value: undefined }),
		resolveCallbackRedirect: vi.fn().mockReturnValue({ ok: true, value: "/" }),
		setupPassportStrategy: vi.fn().mockResolvedValue(undefined),
	};
}

/** Minimal AppConfig stub used by the route */
const stubConfig: AppConfig = {
	endpoints: {
		login: { url: "/login" },
		client: { url: "http://localhost:3001" },
		authCallback: { url: "/auth/callback" },
	},
} as unknown as AppConfig;

/**
 * Build a minimal express app with the Federation router mounted at "/".
 * The passport stub captures authenticate() calls rather than performing
 * real OAuth redirects, so we can assert call arguments.
 */
function buildApp(
	federationProviders: ReadonlyMap<string, FederationProviderBase>,
	passportStub: {
		authenticate: ReturnType<typeof vi.fn>;
	},
) {
	// passport.authenticate returns a middleware; in tests we short-circuit
	// it with a stub that sends 302 (like real passport would for OAuth start).
	const middlewareStub = vi.fn((_req: unknown, res: { redirect: (url: string) => void }) => {
		res.redirect("/oauth-provider-redirect");
	});
	passportStub.authenticate.mockReturnValue(middlewareStub);

	const app = express();

	// Stub out express-session so the route's req.session works
	app.use((req, _res, next) => {
		(req as unknown as { session: Record<string, unknown> }).session = {
			save: (cb: (err: null) => void) => cb(null),
			oauth_csrf_state: undefined,
			regenerate: (cb: (err: null) => void) => cb(null),
		};
		next();
	});

	const router = createRouter(express, {
		passport: passportStub as unknown as PassportStatic,
		config: stubConfig,
		federationProviders,
	});

	app.use(router);
	return app;
}

describe("Federation routes — :name param", () => {
	let mockPassport: { authenticate: ReturnType<typeof vi.fn> };

	beforeEach(() => {
		mockPassport = { authenticate: vi.fn() };
	});

	// ------------------------------------------------------------------
	// Authenticate route
	// ------------------------------------------------------------------

	describe("GET /oauth/federation/:name (authenticate)", () => {
		it("calls passport.authenticate(provider.name) with spread provider.scope", async () => {
			const provider = makeMockProvider("google", ["profile", "email"]);
			const providers = new Map([["google", provider]]);
			const app = buildApp(providers, mockPassport);

			await request(app).get("/oauth/federation/google");

			expect(mockPassport.authenticate).toHaveBeenCalledWith(
				"google",
				expect.objectContaining({ scope: ["profile", "email"] }),
			);
		});

		it("returns 404 for unknown :name on authenticate route", async () => {
			const provider = makeMockProvider("google", []);
			const providers = new Map([["google", provider]]);
			const app = buildApp(providers, mockPassport);

			const res = await request(app).get("/oauth/federation/nonexistent");

			expect(res.status).toBe(404);
		});

		it("supports multi-tenant instance: uses strategy name 'google-work'", async () => {
			const provider = makeMockProvider("google-work", ["profile"]);
			const providers = new Map([["google-work", provider]]);
			const app = buildApp(providers, mockPassport);

			await request(app).get("/oauth/federation/google-work");

			expect(mockPassport.authenticate).toHaveBeenCalledWith(
				"google-work",
				expect.objectContaining({}),
			);
		});
	});

	// ------------------------------------------------------------------
	// Callback route
	// ------------------------------------------------------------------

	describe("GET /oauth/federation/:name/callback", () => {
		it("returns 404 for unknown :name on callback route", async () => {
			const provider = makeMockProvider("google", []);
			const providers = new Map([["google", provider]]);
			const app = buildApp(providers, mockPassport);

			const res = await request(app).get("/oauth/federation/nonexistent/callback");

			expect(res.status).toBe(404);
		});
	});
});
