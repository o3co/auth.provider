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
 * `POST /oauth/device/verification` against cross-site requests.
 *
 * The endpoint authorises on the end-user session cookie alone, which is
 * exactly the credential a browser attaches to a request another site made.
 * RFC 8628 §5.4's remote-phishing attack needs nothing more: any public
 * `client_id` obtains a `user_code`, lures a logged-in user to a page that
 * auto-submits `action=approve&user_code=...`, and polls `/oauth/token` for
 * the victim's access token. `verification_uri_complete = false` exists to
 * keep the user typing the code; a forged POST types it for them.
 *
 * Two layers, both observable only through the router the module mounts —
 * the handler alone never sees a body parser or a guard:
 *
 *   1. JSON only. A form-encoded POST is a "simple" request the browser
 *      sends without a preflight; `application/json` is not.
 *   2. The same CSRF guard `/session/login` runs (#272): a foreign `Origin` /
 *      `Referer` is refused outright, same-origin or `session.csrf.trustedOrigins`
 *      is accepted, and a request with no origin signal at all must carry the
 *      session's signed double-submit token. One policy, not a second one.
 */

import type { ClientRepository } from "@o3co/auth-provider-core";
import { createMemoryDeviceCodeStore, createMemoryRateLimiter } from "@o3co/auth-provider-core";
import { createCsrfProtectionFromConfig } from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { deviceGrantModule } from "#/module.mjs";

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

/** The `session.*` slice the guard is built from — the same one `/session/login` reads. */
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

const makeDeps = (overrides: { session?: unknown } = {}) => {
	const store = createMemoryDeviceCodeStore();
	const logger = makeLogger();
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
				},
			},
			rateLimit: { failMode: "open" },
			...("session" in overrides ? { session: overrides.session } : { session: SESSION_SLICE }),
		},
		clientRepository,
		deviceCodeStore: store,
		rateLimiter: createMemoryRateLimiter({
			limits: { device_verification: { limit: 50, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		}),
		logger,
	};
	return { deps, store, logger };
};

/** Mount the module's contributed verification route behind a fixed session. */
const mountVerification = (deps: Record<string, unknown>) => {
	const factory = deviceGrantModule.contributes?.routes?.[1] as (d: unknown) => {
		mountPath: string;
		handler: express.RequestHandler;
	};
	const route = factory(deps);
	const app = express();
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = {
			isAuthenticated: true,
			user: { id: "user-1" },
		};
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
		// The header-less client is the case the pre-#272 guard waved through.
		// Same policy here: no `Origin`, no `Referer`, no token — refused.
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

	it("does not parse a form body even from the same origin — the endpoint is JSON-only", async () => {
		// Layer one on its own: with no form parser mounted, a form body
		// carries no `action`, so nothing is decided even when the origin arm
		// would have let it through.
		const { deps, store } = makeDeps();
		await seedPending(store);
		const app = mountVerification(deps);

		const res = await request(app)
			.post("/oauth/device/verification")
			.set("Host", SERVER_HOST)
			.set("Origin", `http://${SERVER_HOST}`)
			.type("form")
			.send(`action=approve&user_code=${DISPLAYED_CODE}`);

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect(await isStillPending(store)).toBe(true);
	});

	it("refuses to mount the route without the session config slice it builds the guard from", () => {
		// No slice, no signing key for the token arm and no cookie name to
		// read: the guard cannot be built. Fail where the operator can see it.
		const { deps } = makeDeps({ session: undefined });
		const factory = deviceGrantModule.contributes?.routes?.[1] as (d: unknown) => unknown;
		expect(() => factory(deps)).toThrow(/session/);
	});
});
