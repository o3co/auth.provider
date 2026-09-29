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
 * `POST /oauth/device/verification` against cross-site requests (RFC 8628
 * §5.4's remote phishing): the endpoint authorises on the session cookie
 * alone, which a browser attaches to a request another site made. Two layers,
 * exercised through the router the module mounts: JSON only (a form POST is a
 * "simple" request sent without a preflight), and the CSRF guard
 * `/session/login` runs, from the `csrfGuard` slot the session module
 * provides. The tests fill the slot with the session package's guard, built
 * as the session module builds it. See the package README, "JSON only, behind
 * the session CSRF guard".
 */

import type { AppConfig, ClientRepository, Logger } from "@o3co/auth-provider-core";
import { createMemoryDeviceCodeStore, createMemoryRateLimiter } from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import {
	createCsrfProtectionFromConfig,
	createSessionCsrfGuard,
} from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { deviceGrantModule } from "#/module.mjs";
import { liveCookieSession, liveSessionStore } from "./liveSessions.mjs";

const CLIENT_ID = "tv-app";
const USER_CODE = "BCDFGHJK";
const DISPLAYED_CODE = "BCDF-GHJK";
const SERVER_HOST = "as.example.test";
const TRUSTED_ORIGIN = "https://device.example.test";
const FOREIGN_ORIGIN = "https://evil.example";

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

/** The `session.*` slice the session module builds the guard from — the same one `/session/login` reads. */
const SESSION_SLICE = {
	secret: "test-session-secret.at-least-32-bytes.ok",
	name: "auth.session",
	secure: false,
	sameSite: "lax" as const,
	domain: null,
	csrf: { trustedOrigins: [TRUSTED_ORIGIN] },
};

const makeLogger = () => ({
	warn: vi.fn(),
	info: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
});

const makeDeps = (overrides: { csrfGuard?: unknown } = {}) => {
	const store = createMemoryDeviceCodeStore();
	const logger = makeLogger();
	// The slot's guard, on the logger the route's other lines go to.
	const csrfGuard = createSessionCsrfGuard({
		csrf: createCsrfProtectionFromConfig(SESSION_SLICE),
		trustedOrigins: SESSION_SLICE.csrf.trustedOrigins,
		logger: logger as unknown as Logger,
	});
	const deps = {
		config: {
			oauth: {
				jwt: { issuer: `https://${SERVER_HOST}` },
				accessToken: { expiresIn: 300 },
				deviceAuthorization: {
					enabled: true,
					"verification-uri": "https://example.test/device",
					"verification-uri-complete": false,
					"code-lifetime-seconds": 600,
					"polling-interval-seconds": 5,
					// Present because the module refuses to mount without it;
					// the limiter below declares the prefix explicitly, so the seed
					// never runs here and the numbers need not agree.
					rateLimit: { limit: 50, windowSeconds: 300 },
				},
			},
			rateLimit: { failMode: "open" },
		},
		clientRepository,
		deviceCodeStore: store,
		userSessionStore: liveSessionStore(),
		sessionRequirementResolver: resolverForTests([]),
		rateLimiter: createMemoryRateLimiter({
			limits: { device_verification: { limit: 50, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		}),
		logger,
		...("csrfGuard" in overrides
			? overrides.csrfGuard === undefined
				? {}
				: { csrfGuard: overrides.csrfGuard }
			: { csrfGuard }),
	};
	return { deps, store, logger };
};

/** The verification route of the module built for `deps.config`, as `createApp` would call it. */
const verificationRouteFor = (deps: { readonly config: unknown }) =>
	deviceGrantModule({ config: deps.config as AppConfig }).contributes?.routes?.[1] as (
		d: unknown,
	) => {
		mountPath: string;
		handler: express.RequestHandler;
	};

/** Mount the module's contributed verification route behind a fixed session. */
const mountVerification = (deps: { readonly config: unknown }) => {
	const route = verificationRouteFor(deps)(deps);
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = liveCookieSession();
		next();
	});
	app.use(route.mountPath, route.handler);
	return app;
};

const seedPending = (store: ReturnType<typeof createMemoryDeviceCodeStore>) =>
	store.create({
		deviceCode: "dc-1",
		userCode: USER_CODE,
		clientId: CLIENT_ID,
		requestedScope: ["openid"],
		expiresAtMs: Date.now() + 600_000,
		intervalSeconds: 5,
	});

const isStillPending = async (store: ReturnType<typeof createMemoryDeviceCodeStore>) =>
	(await store.findPendingByUserCode(USER_CODE, Date.now())) !== null;

describe("device verification — cross-site requests (RFC 8628 §5.4)", () => {
	it("refuses a cross-site form POST, and leaves the code pending", async () => {
		// The attack as written: an auto-submitting form on another origin.
		// Form bodies are simple requests, so the browser sends this with the
		// victim's session cookie and no preflight.
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Origin", FOREIGN_ORIGIN)
			.type("form")
			.send(`action=approve&user_code=${DISPLAYED_CODE}`);

		expect(res.status).toBe(403);
		expect(res.body.error).toBe("access_denied");
		expect(await isStillPending(store)).toBe(true);
	});

	it("refuses a cross-origin JSON POST with a foreign Origin, and logs the origin", async () => {
		// A JSON body is preflighted, so a browser never sends this one — but
		// the guard must not rely on that alone: `Origin` is the positive
		// evidence, and a foreign one is refused with its own reason.
		const { deps, store, logger } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Origin", FOREIGN_ORIGIN)
			.send({ action: "approve", user_code: DISPLAYED_CODE });

		expect(res.status).toBe(403);
		expect(res.body.error).toBe("access_denied");
		expect(res.body.error_description).toMatch(/origin/i);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ origin: FOREIGN_ORIGIN }),
			"csrf_origin_rejected",
		);
		expect(await isStillPending(store)).toBe(true);
	});

	it("refuses a foreign Origin on lookup and deny too — one guard for the whole route", async () => {
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		for (const action of ["lookup", "deny"]) {
			const res = await request(app)
				.post("/oauth/device/verification")
				.set("Origin", FOREIGN_ORIGIN)
				.send({ action, user_code: DISPLAYED_CODE });
			expect(res.status).toBe(403);
		}
		expect(await isStillPending(store)).toBe(true);
	});

	it("accepts a same-origin approval", async () => {
		// The deployment's own verification page, served from the provider.
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Host", SERVER_HOST)
			.set("Origin", `http://${SERVER_HOST}`)
			.send({ action: "approve", user_code: DISPLAYED_CODE });

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ status: "approved", client_id: CLIENT_ID });
		expect(await isStillPending(store)).toBe(false);
	});

	it("accepts an approval from an origin listed in session.csrf.trustedOrigins", async () => {
		// A verification page hosted on another origin still works — by
		// declaration, on the same list `/session/login` trusts.
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Origin", TRUSTED_ORIGIN)
			.send({ action: "approve", user_code: DISPLAYED_CODE });

		expect(res.status).toBe(200);
		expect(res.body.status).toBe("approved");
	});

	it("refuses a request with no origin signal and no token (the session guard's rule)", async () => {
		// No `Origin`, no `Referer`, no token: refused.
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		const res = await request(app)
			.post("/oauth/device/verification")
			.send({ action: "approve", user_code: DISPLAYED_CODE });

		expect(res.status).toBe(403);
		expect(res.body.error).toBe("access_denied");
		expect(await isStillPending(store)).toBe(true);
	});

	it("accepts a header-less client that presents the session's double-submit token", async () => {
		// The other half of that rule: the token minted by `GET /session/csrf`
		// — derived from the same `session.*` slice — is what a non-browser
		// client sends instead of an `Origin`.
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);
		const csrf = createCsrfProtectionFromConfig(SESSION_SLICE);
		const token = csrf.mint();

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Cookie", `${csrf.cookieName}=${token}`)
			.set(csrf.headerName, token)
			.send({ action: "approve", user_code: DISPLAYED_CODE });

		expect(res.status).toBe(200);
		expect(res.body.status).toBe("approved");
	});

	it("refuses a form body even from the same origin — the endpoint is JSON-only", async () => {
		// Layer one on its own: the origin arm would let this through, and
		// the media type alone refuses it, so nothing is decided.
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Host", SERVER_HOST)
			.set("Origin", `http://${SERVER_HOST}`)
			.type("form")
			.send(`action=approve&user_code=${DISPLAYED_CODE}`);

		expect(res.status).toBe(415);
		expect(res.body.error).toBe("invalid_request");
		expect(await isStillPending(store)).toBe(true);
	});

	it("refuses to mount the enabled route without a csrfGuard, naming the component", () => {
		// No guard, no CSRF defence on a route that authorises on the session
		// cookie: fail where the operator can see it, not on the first forged
		// approval.
		const { deps } = makeDeps({ csrfGuard: undefined });
		const factory = verificationRouteFor(deps);
		expect(() => factory(deps)).toThrow(/requires a csrfGuard component/);
	});
});
