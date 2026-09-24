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
 * RFC 6749 Appendix A.7 / A.8 on the session router, booted through core's
 * `createApp` with `sessionModule`: the error text `/session/*` sends stays
 * inside `1*NQSCHAR` (printable ASCII without `"` and `\`) — its own text,
 * a configured federation's name, and what a limiter adapter or a
 * contributed redirect policy hands it.
 */

import type {
	AppConfig,
	FederationProvider,
	FederationTokenStore,
	RateLimitDecision,
	RateLimiter,
	SessionFederationIndex,
	UserRepository,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { defineModule } from "@o3co/auth-provider-core";
import { createTestApp, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import type { FederationRedirectPolicy } from "#/federations/redirect-policy.mjs";
import { sessionModule } from "#/module.mjs";
import { sessionStoreModuleFor } from "#/modules/sessionStoreModule.mjs";

/** Every character a contributed text might carry that RFC 6749 does not allow. */
const HOSTILE = 'say "hi" \\ see §3 — café\r\nX-Injected: 1 \u{1F600}';
/** What the wire carries instead: each code point outside the set is one `?`. */
const HOSTILE_ON_THE_WIRE = "say ?hi? ? see ?3 ? caf???X-Injected: 1 ?";

const providing = <T,>(name: string, slot: string, value: T) =>
	defineModule({ name, provides: { [slot]: () => value } as never });

const stores = [
	providing("test:user-repository", "userRepository", {
		authenticate: async () => null,
		authenticateByToken: async () => null,
	} as unknown as UserRepository),
	providing("test:user-session-store", "userSessionStore", {
		kind: "memory",
		async create() {},
		async get() {
			return null;
		},
		async delete() {},
	} as unknown as UserSessionStore),
	providing("test:federation-token-store", "federationTokenStore", {
		kind: "memory",
		async attach() {},
		async get() {
			return null;
		},
		async update() {},
		async removeBySid() {},
		async delete() {},
	} as unknown as FederationTokenStore),
	providing("test:session-federation-index", "sessionFederationIndex", {
		kind: "memory",
		async addFederation() {},
		async listFederations() {
			return [];
		},
		async removeFederation() {},
		async removeBySid() {},
	} as unknown as SessionFederationIndex),
	// oauth-package slots the boot validator asks for once a federation is enabled.
	providing("test:session-rp-registry", "sessionRPRegistry", { kind: "stub" }),
	providing("test:session-family-index", "sessionFamilyIndex", { kind: "stub" }),
	providing("test:refresh-token-family-revocation", "refreshTokenFamilyRevocation", {
		kind: "stub",
	}),
];

/** A query-mode federation named `stub`, and the redirect policy paired with it. */
const federationModule = (policy: FederationRedirectPolicy) =>
	defineModule({
		name: "test:stub-federation",
		contributes: {
			federations: {
				stub: (): FederationProvider => ({
					name: "stub",
					scope: ["openid"],
					buildAuthorizationUrl: () => new URL("https://idp.example/authorize"),
					exchangeCode: async () => ({
						issuer: "https://idp.example",
						sub: "user-1",
						expiresAt: null,
					}),
				}),
			},
			federationRedirectPolicies: { stub: () => policy },
		},
	});

const permissivePolicy: FederationRedirectPolicy = {
	validateRedirect: () => ({ ok: true as const, value: undefined }),
	resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
};

const limiterAnswering = (decision: Partial<RateLimitDecision>): RateLimiter => ({
	kind: "custom",
	check: async () => ({ allowed: true, ...decision }) as RateLimitDecision,
});

const config = (): AppConfig => {
	const base = makeValidAppConfig();
	return {
		...base,
		// supertest speaks plain HTTP, so no `Secure` cookie and no `__Host-` name.
		session: { ...base.session, name: "auth.session", secure: false },
		federations: {
			...base.federations,
			stub: {
				enabled: true,
				clientId: "id",
				clientSecret: "secret",
				callbackURL: "https://as.example/session/oauth/federation/stub/callback",
			} as never,
		},
	} as AppConfig;
};

const handles: { dispose(): Promise<void> }[] = [];
afterEach(async () => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
});

const boot = async (
	options: { limiter?: RateLimiter; policy?: FederationRedirectPolicy } = {},
): Promise<express.Express> => {
	const cfg = config();
	const handle = await createTestApp({
		modules: [
			sessionModule,
			sessionStoreModuleFor(cfg),
			...stores,
			federationModule(options.policy ?? permissivePolicy),
			providing("test:rate-limiter", "rateLimiter", options.limiter ?? limiterAnswering({})),
		],
		bootstrapComponents: { config: cfg, pathResolver: (s: string) => s },
	});
	handles.push(handle);
	const app = express();
	app.use(handle.router);
	return app;
};

/** `POST /session/login` past the CSRF guard, with the double-submit token it hands out. */
const login = async (app: express.Express, body: Record<string, unknown>) => {
	const agent = request.agent(app);
	const csrf = await agent.get("/session/csrf");
	expect(csrf.status).toBe(200);
	return agent
		.post("/session/login")
		.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
		.send({ username: "alice", password: "secret", ...body });
};

describe("POST /session/login", () => {
	it("sends a limiter adapter's refusal reason inside RFC 6749's set", async () => {
		const app = await boot({ limiter: limiterAnswering({ allowed: false, reason: HOSTILE }) });
		const res = await login(app, {});
		expect(res.status).toBe(429);
		expect(res.body).toEqual({ error: "rate_limited", error_description: HOSTILE_ON_THE_WIRE });
	});

	it.each([
		[
			"ftp://app.example/",
			"redirect_to must use https, or http for a loopback host (localhost, 127.0.0.0/8, [::1]); no other scheme is accepted (reason: unsupported-scheme)",
		],
		[
			"http://app.example/",
			"redirect_to must use https; http is accepted only for a loopback host (localhost, 127.0.0.0/8, [::1]), where the traffic never leaves the machine (reason: insecure-scheme)",
		],
	])("refuses redirect_to %s in plain ASCII", async (redirectTo, description) => {
		const app = await boot();
		const res = await login(app, { redirect_to: redirectTo });
		expect(res.status).toBe(400);
		expect(res.body).toEqual({ error: "invalid_redirect", error_description: description });
	});
});

describe("/session/oauth/federation/:name", () => {
	it("quotes the federation's name with ' when a query federation is POSTed to", async () => {
		const app = await boot();
		const res = await request(app)
			.post("/session/oauth/federation/stub/callback")
			.type("form")
			.send({ state: "x", code: "y" });
		expect(res.status).toBe(405);
		expect(res.body).toEqual({
			error: "method_not_allowed",
			error_description:
				"Federation 'stub' returns its authorization response in the query string; the POST callback is accepted only for a form_post federation",
		});
	});

	it("sends an unregistered name the client asked for inside RFC 6749's set", async () => {
		const app = await boot();
		const res = await request(app).get(
			`/session/oauth/federation/${encodeURIComponent('st"ub\\é')}`,
		);
		expect(res.status).toBe(404);
		expect(res.body).toEqual({
			error: "not_found",
			error_description: "Federation provider not registered: st?ub??",
		});
	});

	it("sends a contributed redirect policy's refusal inside RFC 6749's set", async () => {
		const app = await boot({
			policy: {
				...permissivePolicy,
				validateRedirect: () => ({
					ok: false as const,
					status: 400,
					error: "invalid_redirect",
					errorDescription: HOSTILE,
				}),
			},
		});
		const res = await request(app)
			.get("/session/oauth/federation/stub")
			.query({ redirect_to: "https://app.example/" });
		expect(res.status).toBe(400);
		expect(res.body).toEqual({ error: "invalid_redirect", error_description: HOSTILE_ON_THE_WIRE });
	});
});
