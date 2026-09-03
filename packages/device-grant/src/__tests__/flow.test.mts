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
 * The RFC 8628 flow end to end (#298): a device asks, a human answers, the
 * device polls.
 *
 * Two devices and three requests that arrive out of order, so most of what is
 * asserted here is *ordering* — what each side sees before the other has
 * acted, and what happens when they act twice.
 */

import type {
	AuditEvent,
	AuditSink,
	AuthenticatedClient,
	ClientRepository,
	GrantContext,
	RateLimiter,
	RateLimitFailMode,
} from "@o3co/auth-provider-core";
import {
	createMemoryDeviceCodeStore,
	createMemoryRateLimiter,
	createSymmetricKeyStore,
	generateUserCode,
	normaliseUserCode,
} from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "@o3co/auth-provider-oauth";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createDeviceAuthorizationHandler } from "#/deviceAuthorizationEndpoint.mjs";
import { createDeviceCodeGrant } from "#/grant.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";
import { createDeviceVerificationHandler } from "#/verificationEndpoint.mjs";

const CLIENT_ID = "tv-app";
const ISSUER = "https://as.example.test";
const VERIFICATION_URI = "https://example.test/device";

const client = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "none" as const,
	allowedScopes: ["openid", "profile"],
	defaultScopes: ["openid"],
	allowedAudiences: ["https://api.example.test"],
	allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
} as unknown as AuthenticatedClient;

/** Registered, but never for this grant — one with an allowlist that omits it, one with none. */
const OTHER_GRANTS_ID = "web-app";
const otherGrantsClient = {
	clientId: OTHER_GRANTS_ID,
	tokenEndpointAuthMethod: "none" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: ["authorization_code"],
} as unknown as AuthenticatedClient;
const NO_ALLOWLIST_ID = "legacy-app";
const noAllowlistClient = {
	clientId: NO_ALLOWLIST_ID,
	tokenEndpointAuthMethod: "none" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
} as unknown as AuthenticatedClient;

/**
 * A confidential registration, to prove that this endpoint enforces the
 * registration's own `tokenEndpointAuthMethod` rather than accepting any
 * known `client_id`.
 */
const CONFIDENTIAL_ID = "backend-app";
const CONFIDENTIAL_SECRET = "s3cret-value";

const confidentialClient = {
	clientId: CONFIDENTIAL_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
} as unknown as AuthenticatedClient;

const clientRepository: ClientRepository = {
	findById: async (id) => {
		if (id === CLIENT_ID) return client as never;
		if (id === CONFIDENTIAL_ID) return confidentialClient as never;
		if (id === OTHER_GRANTS_ID) return otherGrantsClient as never;
		if (id === NO_ALLOWLIST_ID) return noAllowlistClient as never;
		return null;
	},
	authenticate: async (id, secret) =>
		id === CONFIDENTIAL_ID && secret === CONFIDENTIAL_SECRET ? (confidentialClient as never) : null,
};

const settings = {
	verificationUri: VERIFICATION_URI,
	verificationUriComplete: false,
	codeLifetimeSeconds: 600,
	pollingIntervalSeconds: 5,
};

/** A clock the tests move by hand, so polling intervals are not real waits. */
const makeClock = (start = 1_800_000_000_000) => {
	let current = start;
	return {
		now: () => current,
		advance: (ms: number) => {
			current += ms;
		},
	};
};

const makeHarness = (
	overrides: {
		settings?: Partial<typeof settings>;
		rateLimiter?: RateLimiter;
		/** OR-5 outage policy; the harness defaults to the product's `closed`. */
		failMode?: RateLimitFailMode;
		session?: Record<string, unknown>;
		auditSink?: AuditSink;
		logger?: ReturnType<typeof makeLogger>;
		store?: ReturnType<typeof createMemoryDeviceCodeStore>;
	} = {},
) => {
	const clock = makeClock();
	const store = overrides.store ?? createMemoryDeviceCodeStore();
	const resolved = { ...settings, ...(overrides.settings ?? {}) };
	const rateLimiter =
		overrides.rateLimiter ??
		createMemoryRateLimiter({
			limits: { device_verification: { limit: 5, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		});

	const session = overrides.session ?? { isAuthenticated: true, user: { id: "user-1" } };

	const app = express();
	app.use(express.json());
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = session;
		next();
	});
	// The same middleware the module mounts, so these tests exercise the real
	// client-authentication path rather than a hand-set `req.oauthClient`.
	app.post(
		"/oauth/device_authorization",
		createClientAuthMiddleware(clientRepository, {
			issuer: ISSUER,
			allowPublicClients: true,
		}),
		createDeviceAuthorizationHandler({
			store,
			settings: resolved,
			now: clock.now,
		}),
	);
	app.post(
		"/oauth/device/verification",
		createDeviceVerificationHandler({
			store,
			settings: resolved,
			rateLimiter,
			failMode: overrides.failMode ?? "closed",
			now: clock.now,
			...(overrides.auditSink ? { auditSink: overrides.auditSink } : {}),
			...(overrides.logger ? { logger: overrides.logger } : {}),
		}),
	);

	const grant = createDeviceCodeGrant({
		store,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!!"),
		accessTokenExpiresIn: 300,
		now: clock.now,
	});

	const poll = (deviceCode: string, authenticated: AuthenticatedClient | null = client) =>
		grant.handle({
			body: { device_code: deviceCode },
			session: {},
			metadata: {},
			issuer: ISSUER,
			authenticatedClient: authenticated,
		} as unknown as GrantContext);

	return { app, store, clock, grant, poll, rateLimiter };
};

const startDevice = async (app: express.Express, body: Record<string, unknown> = {}) =>
	request(app)
		.post("/oauth/device_authorization")
		.send({ client_id: CLIENT_ID, ...body });

const verify = (app: express.Express, body: Record<string, unknown>) =>
	request(app).post("/oauth/device/verification").send(body);

const makeLogger = () => ({
	warn: vi.fn(),
	info: vi.fn(),
	error: vi.fn(),
	debug: vi.fn(),
});

const makeSink = () => {
	const events: AuditEvent[] = [];
	const sink: AuditSink = {
		kind: "test",
		record: async (event) => {
			events.push(event);
		},
	};
	return { sink, events };
};

/** The sink is fire-and-forget, so give the detached promise a turn. */
const settle = () => new Promise((resolve) => setImmediate(resolve));

/** A limiter whose backend is down: every check rejects, as a Redis client would. */
const brokenLimiter = (): RateLimiter => ({
	kind: "broken",
	check: async () => {
		throw new Error("redis down");
	},
});

describe("device authorization request (RFC 8628 §3.1–§3.2)", () => {
	it("returns the codes, the verification URI, and the polling contract", async () => {
		const { app } = makeHarness();
		const res = await startDevice(app, { scope: "openid profile" });

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({
			verification_uri: VERIFICATION_URI,
			expires_in: 600,
			interval: 5,
		});
		// §6.1: the displayed code is base-20, no vowels, no digits.
		expect(res.body.user_code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
		expect(typeof res.body.device_code).toBe("string");
	});

	it("does not return verification_uri_complete by default", async () => {
		// §5.4: the typing step is the proof the device is in the user's
		// possession. Removing it by default would make remote phishing easier
		// for every deployment that never read the option.
		const { app } = makeHarness();
		const res = await startDevice(app);
		expect(res.body.verification_uri_complete).toBeUndefined();
	});

	it("returns verification_uri_complete when the operator opts in", async () => {
		const { app } = makeHarness({ settings: { verificationUriComplete: true } });
		const res = await startDevice(app);
		const complete = new URL(res.body.verification_uri_complete as string);
		expect(complete.searchParams.get("user_code")).toBe(res.body.user_code);
	});

	it("sets no-store, because the response is a bearer credential", async () => {
		const { app } = makeHarness();
		const res = await startDevice(app);
		expect(res.headers["cache-control"]).toContain("no-store");
	});

	it("refuses a confidential client identified by client_id alone", async () => {
		// RFC 8628 §3.1 applies RFC 6749 §3.2.1's client-authentication
		// requirements here. Without them anyone could open pending
		// authorizations in a confidential client's name and phish a user into
		// approving one.
		const { app } = makeHarness();
		const res = await request(app)
			.post("/oauth/device_authorization")
			.send({ client_id: CONFIDENTIAL_ID });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});

	it("accepts a confidential client that authenticates", async () => {
		const { app } = makeHarness();
		const res = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, CONFIDENTIAL_SECRET)
			.send({});
		expect(res.status).toBe(200);
		expect(typeof res.body.device_code).toBe("string");
	});

	it("refuses a confidential client with the wrong secret", async () => {
		const { app } = makeHarness();
		const res = await request(app)
			.post("/oauth/device_authorization")
			.auth(CONFIDENTIAL_ID, "wrong")
			.send({});
		expect(res.status).toBe(401);
	});

	it("still accepts a public device client on client_id alone (§5.6)", async () => {
		// The other half of the same rule: device clients "should be treated
		// as public clients", so requiring a secret from them would make the
		// grant unusable for what it exists to serve.
		const { app } = makeHarness();
		const res = await startDevice(app);
		expect(res.status).toBe(200);
	});

	it("refuses an unknown client", async () => {
		const { app } = makeHarness();
		const res = await startDevice(app, { client_id: "not-registered" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});

	it("refuses a client whose allowedGrantTypes omit the device grant", async () => {
		// The token endpoint would refuse the device_code exchange for this
		// client, so letting it open a pending authorization only produces a
		// real-looking prompt — the exact material a phishing page needs —
		// for a grant that can never complete.
		const { app } = makeHarness();
		const res = await startDevice(app, { client_id: OTHER_GRANTS_ID });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
		expect(res.body.error_description).toContain(DEVICE_CODE_GRANT_TYPE);
	});

	it("refuses a client with no allowedGrantTypes at all (#326: never acquired by omission)", async () => {
		// The grant declares requiresExplicitGrantAllowlist, so the token
		// endpoint denies by absence for it. The authorization endpoint
		// applies the same rule, or the two disagree about who may start
		// what only one of them will finish.
		const { app } = makeHarness();
		const res = await startDevice(app, { client_id: NO_ALLOWLIST_ID });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});

	it("refuses a scope the client is not registered for", async () => {
		const { app } = makeHarness();
		const res = await startDevice(app, { scope: "openid admin" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_scope");
		expect(res.body.error_description).toContain("admin");
	});

	it("draws an omitted scope from defaultScopes, never the whole allowlist", async () => {
		// #396's rule, applied here: "forgot to send scope" must not be the
		// maximum grant. The client allows openid+profile and defaults to
		// openid.
		const { app, store, clock } = makeHarness();
		const res = await startDevice(app);
		const userCode = normaliseUserCode(res.body.user_code as string);
		// The harness clock, not `Date.now()`: the synthetic clock starts in the
		// future, so a wall-clock read would report the record expired the day
		// real time passes that start and turn this into a dated failure.
		const pending = await store.findPendingByUserCode(userCode as string, clock.now());
		expect(pending?.requestedScope).toEqual(["openid"]);
	});
});

describe("verification endpoint", () => {
	it("tells the page which client is asking and for what", async () => {
		// §5.4 recommends informing the user what they are authorizing. The
		// page cannot do that without this.
		const { app } = makeHarness();
		const started = await startDevice(app, { scope: "openid profile" });
		const res = await verify(app, { action: "lookup", user_code: started.body.user_code });

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ client_id: CLIENT_ID, scope: "openid profile" });
	});

	it("accepts the code as displayed, lower-cased, or unseparated", async () => {
		const { app } = makeHarness();
		const started = await startDevice(app);
		const displayed = started.body.user_code as string;

		for (const typed of [displayed, displayed.toLowerCase(), displayed.replace("-", "")]) {
			const res = await verify(app, { action: "lookup", user_code: typed });
			expect(res.status).toBe(200);
		}
	});

	it("requires an authenticated end user", async () => {
		const { app } = makeHarness({ session: { isAuthenticated: false } });
		const res = await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("login_required");
	});

	it("answers a malformed code exactly as it answers an unknown one", async () => {
		// Distinguishing "well-formed but unknown" from "malformed" narrows the
		// search space for free.
		const { app } = makeHarness();
		const malformed = await verify(app, { action: "lookup", user_code: "0000-0000" });
		const unknown = await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });

		expect(malformed.status).toBe(unknown.status);
		expect(malformed.body).toEqual(unknown.body);
	});

	it("refuses an action it does not implement", async () => {
		const { app } = makeHarness();
		const res = await verify(app, { action: "revoke", user_code: "BCDF-GHJK" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
	});
});

describe("rate limiting (RFC 8628 §5.1)", () => {
	it("counts lookups against the same budget as approvals", async () => {
		// The lookup is the same brute-force oracle: it answers "is this a real
		// code?". A lookup route that did not count would be a free oracle
		// beside a limited one.
		const rateLimiter = createMemoryRateLimiter({
			limits: { device_verification: { limit: 3, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		});
		const { app } = makeHarness({ rateLimiter });

		const statuses: number[] = [];
		for (let i = 0; i < 5; i++) {
			const res = await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
			statuses.push(res.status);
		}
		expect(statuses).toEqual([404, 404, 404, 429, 429]);
	});

	it("counts a malformed code as an attempt", async () => {
		// Excluding malformed input would hand an attacker an unmetered way to
		// probe which shapes the endpoint accepts.
		const rateLimiter = createMemoryRateLimiter({
			limits: { device_verification: { limit: 2, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		});
		const { app } = makeHarness({ rateLimiter });

		await verify(app, { action: "lookup", user_code: "!!!!" });
		await verify(app, { action: "lookup", user_code: "!!!!" });
		const third = await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
		expect(third.status).toBe(429);
	});

	it("keys the budget on the user, not the code", async () => {
		// Keying on the code would spend whichever code the attacker happened
		// to hit, which is nobody's budget. Keying on the subject means an
		// attacker needs an account and burns their own.
		const rateLimiter = createMemoryRateLimiter({
			limits: { device_verification: { limit: 2, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		});
		const spy = { check: vi.fn(rateLimiter.check), kind: rateLimiter.kind };
		const { app } = makeHarness({ rateLimiter: spy as RateLimiter });

		await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
		expect(spy.check).toHaveBeenCalledWith(
			"device_verification:user:user-1",
			expect.objectContaining({ userId: "user-1" }),
		);
	});
});

describe("audit trail for the human's decision", () => {
	// The decision that turns a code into a token used to reach nothing but
	// `logger.info` — optional, unstructured, and not the pipeline the rest of
	// the product's security events flow through. A device authorization is
	// a consent event with a subject and a client; it belongs in the sink.

	it("records device.approved with the subject, the client and the scope", async () => {
		const { sink, events } = makeSink();
		const { app } = makeHarness({ auditSink: sink });
		const started = await startDevice(app, { scope: "openid profile" });

		await verify(app, { action: "approve", user_code: started.body.user_code });
		await settle();

		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "device.approved",
			subject: "user-1",
			clientId: CLIENT_ID,
			details: { scope: "openid profile" },
		});
		expect(events[0]?.timestamp).toBeInstanceOf(Date);
	});

	it("records device.denied", async () => {
		const { sink, events } = makeSink();
		const { app } = makeHarness({ auditSink: sink });
		const started = await startDevice(app);

		await verify(app, { action: "deny", user_code: started.body.user_code });
		await settle();

		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "device.denied",
			subject: "user-1",
			clientId: CLIENT_ID,
		});
	});

	it("records device.rate_limited when the subject's budget runs out", async () => {
		// The 429 is the signal that someone is guessing codes from an account
		// — exactly what a dashboard wants to see, and exactly what a
		// `logger.warn` nobody tails does not deliver.
		const { sink, events } = makeSink();
		const logger = makeLogger();
		const rateLimiter = createMemoryRateLimiter({
			limits: { device_verification: { limit: 1, windowSeconds: 300 } },
			defaultLimit: { limit: 60, windowSeconds: 60 },
		});
		const spy = { check: vi.fn(rateLimiter.check), kind: rateLimiter.kind };
		const { app } = makeHarness({ auditSink: sink, rateLimiter: spy as RateLimiter, logger });

		await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
		const limited = await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
		await settle();

		expect(limited.status).toBe(429);
		expect(limited.body.error).toBe("slow_down");
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "device.rate_limited",
			subject: "user-1",
			details: { action: "lookup", remaining: 0 },
		});
		// #457 moved the check behind the shared outage policy; the budget is
		// still the subject's, and the operator-facing line still fires.
		expect(spy.check.mock.calls.map(([key]) => key)).toEqual([
			"device_verification:user:user-1",
			"device_verification:user:user-1",
		]);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ subject: "user-1", action: "lookup", remaining: 0 }),
			"device_verification_rate_limited",
		);
	});

	it.each(["open", "closed"] as const)(
		"answers 429 for an exhausted budget under failMode = %s — the policy is for outages, not decisions",
		async (failMode) => {
			// `failMode = "open"` waves a request through when the limiter has
			// no answer; a limiter that answered "no" is not that case.
			const { sink, events } = makeSink();
			const rateLimiter = createMemoryRateLimiter({
				limits: { device_verification: { limit: 1, windowSeconds: 300 } },
				defaultLimit: { limit: 60, windowSeconds: 60 },
			});
			const { app } = makeHarness({ auditSink: sink, rateLimiter, failMode });

			await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
			const limited = await verify(app, { action: "lookup", user_code: "BCDF-GHJK" });
			await settle();

			expect(limited.status).toBe(429);
			expect(events.map((e) => e.type)).toEqual(["device.rate_limited"]);
		},
	);

	it("never puts the code itself in an event", async () => {
		// The user code is the thing being brute-forced and the device code is
		// a bearer credential; an audit pipeline is not a place for either.
		const { sink, events } = makeSink();
		const { app } = makeHarness({ auditSink: sink });
		const started = await startDevice(app);
		const displayed = started.body.user_code as string;

		await verify(app, { action: "approve", user_code: displayed });
		await settle();

		const serialised = JSON.stringify(events);
		expect(serialised).not.toContain(displayed);
		expect(serialised).not.toContain(normaliseUserCode(displayed));
		expect(serialised).not.toContain(started.body.device_code);
	});

	it("records nothing — and still decides — when no sink is wired", async () => {
		const { app, clock, poll } = makeHarness();
		const started = await startDevice(app);
		const res = await verify(app, { action: "approve", user_code: started.body.user_code });
		expect(res.status).toBe(200);
		clock.advance(10_000);
		expect((await poll(started.body.device_code as string)).result.status).toBe(200);
	});
});

describe("limiter outage — rateLimit.failMode applies here too (#457)", () => {
	// Until #457 this endpoint called `rateLimiter.check` outside
	// `createRateLimitGuard`, so a limiter-backend outage was an unhandled
	// throw: 500 through the terminal handler, `failMode` ignored, and no
	// `rate_limit.unavailable` event for the alert operators page on — on the
	// one endpoint RFC 8628 §5.1 sizes the user code's entropy against.

	it('failMode = "closed": answers 503 with the guard\'s envelope and does not decide', async () => {
		const { app, store, clock } = makeHarness({
			rateLimiter: brokenLimiter(),
			failMode: "closed",
			logger: makeLogger(),
		});
		const started = await startDevice(app);

		const res = await verify(app, { action: "approve", user_code: started.body.user_code });

		expect(res.status).toBe(503);
		// The same body every guarded route answers, so a client and a
		// dashboard see one outage shape rather than two.
		expect(res.body).toEqual({
			error: "service_unavailable",
			error_description: "Rate limiter temporarily unavailable",
		});
		expect(res.headers["cache-control"]).toContain("no-store");
		// The approval did not happen: the code is still pending.
		const userCode = normaliseUserCode(started.body.user_code as string) as string;
		expect(await store.findPendingByUserCode(userCode, clock.now())).not.toBeNull();
	});

	it('failMode = "closed": emits rate_limit.unavailable with the guard\'s fields, and no device.rate_limited', async () => {
		const { sink, events } = makeSink();
		const logger = makeLogger();
		const { app } = makeHarness({
			rateLimiter: brokenLimiter(),
			failMode: "closed",
			auditSink: sink,
			logger,
		});

		await request(app)
			.post("/oauth/device/verification")
			.set("User-Agent", "device-test/1.0")
			.send({ action: "lookup", user_code: "BCDF-GHJK" });
		await settle();

		expect(events.map((e) => e.type)).toEqual(["rate_limit.unavailable"]);
		expect(events[0]).toMatchObject({
			type: "rate_limit.unavailable",
			userAgent: "device-test/1.0",
			details: { tag: "device_verification", error: "redis down" },
		});
		expect(typeof events[0]?.ip).toBe("string");
		expect(events[0]?.timestamp).toBeInstanceOf(Date);
		// An outage is not a subject guessing codes: the #443 signal stays
		// reserved for a limiter that answered "no".
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ error: "redis down", mode: "closed", tag: "device_verification" }),
			"rate_limiter_failed_closed",
		);
		expect(logger.warn).not.toHaveBeenCalledWith(
			expect.anything(),
			"device_verification_rate_limited",
		);
	});

	it.each(["lookup", "approve", "deny"] as const)(
		'failMode = "open": lets %s proceed and reports the outage',
		async (action) => {
			const { sink, events } = makeSink();
			const logger = makeLogger();
			const { app } = makeHarness({
				rateLimiter: brokenLimiter(),
				failMode: "open",
				auditSink: sink,
				logger,
			});
			const started = await startDevice(app);

			const res = await verify(app, { action, user_code: started.body.user_code });
			await settle();

			expect(res.status).toBe(200);
			expect(res.body.client_id).toBe(CLIENT_ID);
			expect(events.map((e) => e.type)).toContain("rate_limit.unavailable");
			expect(logger.error).toHaveBeenCalledWith(
				expect.objectContaining({ error: "redis down", mode: "open", tag: "device_verification" }),
				"rate_limiter_failed_open",
			);
		},
	);

	it('failMode = "open": an approval made during the outage is a real approval', async () => {
		// Fail-open means the request is served as if allowed, all the way to
		// the device collecting its token — not half-served.
		const { app, poll, clock } = makeHarness({ rateLimiter: brokenLimiter(), failMode: "open" });
		const started = await startDevice(app);

		const approval = await verify(app, { action: "approve", user_code: started.body.user_code });
		expect(approval.status).toBe(200);

		clock.advance(10_000);
		expect((await poll(started.body.device_code as string)).result.status).toBe(200);
	});

	it("still answers 401 and 400 before consulting the limiter at all", async () => {
		// The outage policy sits where the check sits: after the session and
		// the action are validated. An anonymous caller during an outage is
		// still told to log in, not that the limiter is down.
		const anonymous = makeHarness({
			rateLimiter: brokenLimiter(),
			failMode: "closed",
			session: { isAuthenticated: false },
		});
		const unauthenticated = await verify(anonymous.app, {
			action: "lookup",
			user_code: "BCDF-GHJK",
		});
		expect(unauthenticated.status).toBe(401);

		const { app } = makeHarness({ rateLimiter: brokenLimiter(), failMode: "closed" });
		const badAction = await verify(app, { action: "revoke", user_code: "BCDF-GHJK" });
		expect(badAction.status).toBe(400);
	});
});

describe("polling (RFC 8628 §3.5)", () => {
	it("answers authorization_pending until the user acts", async () => {
		const { app, poll } = makeHarness();
		const started = await startDevice(app);
		const result = await poll(started.body.device_code as string);
		expect(result.result).toMatchObject({ status: 400, error: "authorization_pending" });
	});

	it("answers slow_down and widens the interval it enforces", async () => {
		// §3.5: "the interval MUST be increased by 5 seconds for this and all
		// subsequent requests". A server that says slow_down while still
		// measuring against the original interval tells a compliant client to
		// slow down forever.
		const { app, poll, clock } = makeHarness();
		const started = await startDevice(app);
		const deviceCode = started.body.device_code as string;

		await poll(deviceCode);
		clock.advance(1_000);
		const tooSoon = await poll(deviceCode);
		expect(tooSoon.result).toMatchObject({ status: 400, error: "slow_down" });

		// Past the original 5s but inside the widened 10s: still too soon.
		clock.advance(6_000);
		expect((await poll(deviceCode)).result).toMatchObject({ error: "slow_down" });

		// Past the widened interval: a normal answer again.
		clock.advance(30_000);
		expect((await poll(deviceCode)).result).toMatchObject({ error: "authorization_pending" });
	});

	it("issues a token once the user approves, and never twice", async () => {
		const { app, poll, clock } = makeHarness();
		const started = await startDevice(app, { scope: "openid profile" });
		const deviceCode = started.body.device_code as string;

		const approval = await verify(app, {
			action: "approve",
			user_code: started.body.user_code,
		});
		expect(approval.status).toBe(200);
		expect(approval.body).toMatchObject({ status: "approved", client_id: CLIENT_ID });

		clock.advance(10_000);
		const first = await poll(deviceCode);
		expect(first.result.status).toBe(200);
		expect("tokens" in first.result && first.result.tokens.access_token).toBeTruthy();

		// The approval is spent. A replayed device_code is answered exactly as
		// an invented one is.
		clock.advance(10_000);
		expect((await poll(deviceCode)).result).toMatchObject({
			status: 400,
			error: "invalid_grant",
		});
	});

	it("answers access_denied when the user says no, and stops there", async () => {
		const { app, poll, clock } = makeHarness();
		const started = await startDevice(app);
		const deviceCode = started.body.device_code as string;

		await verify(app, { action: "deny", user_code: started.body.user_code });

		clock.advance(10_000);
		expect((await poll(deviceCode)).result).toMatchObject({
			status: 400,
			error: "access_denied",
		});
	});

	it("refuses to reverse a denial", async () => {
		// A user who denied a phishing prompt must not be talked into "just
		// trying again".
		const { app } = makeHarness();
		const started = await startDevice(app);
		await verify(app, { action: "deny", user_code: started.body.user_code });

		const second = await verify(app, { action: "approve", user_code: started.body.user_code });
		expect(second.status).toBe(409);
		expect(second.body.error_description).toContain("denied");
	});

	it("answers expired_token once the window closes", async () => {
		const { app, poll, clock } = makeHarness();
		const started = await startDevice(app);
		clock.advance(601 * 1000);
		expect((await poll(started.body.device_code as string)).result).toMatchObject({
			status: 400,
			error: "expired_token",
		});
	});

	it("refuses a device_code redeemed by a different client", async () => {
		// A leaked device code must not be redeemable by another registered
		// client, or the leak becomes a full impersonation of the approval.
		const { app, poll, clock } = makeHarness();
		const started = await startDevice(app);
		await verify(app, { action: "approve", user_code: started.body.user_code });

		clock.advance(10_000);
		const other = { ...client, clientId: "another-app" } as AuthenticatedClient;
		expect((await poll(started.body.device_code as string, other)).result).toMatchObject({
			status: 400,
			error: "invalid_grant",
		});
	});

	it("requires an authenticated client", async () => {
		const { app, poll } = makeHarness();
		const started = await startDevice(app);
		expect((await poll(started.body.device_code as string, null)).result).toMatchObject({
			status: 401,
			error: "invalid_client",
		});
	});

	it("requires a device_code", async () => {
		const { poll } = makeHarness();
		expect((await poll("")).result).toMatchObject({ status: 400, error: "invalid_request" });
	});

	it("declares that it must never be acquired by omission (#326)", () => {
		const { grant } = makeHarness();
		expect(grant.requiresExplicitGrantAllowlist).toBe(true);
	});
});

describe("the token carries what was approved", () => {
	it("names the approving subject, the client, and the granted scope", async () => {
		const { app, poll, clock } = makeHarness();
		const started = await startDevice(app, { scope: "openid profile" });
		await verify(app, { action: "approve", user_code: started.body.user_code });

		clock.advance(10_000);
		const result = await poll(started.body.device_code as string);
		if (!("tokens" in result.result)) throw new Error("expected a token response");

		const [, payloadB64] = result.result.tokens.access_token.split(".");
		const payload = JSON.parse(Buffer.from(payloadB64 as string, "base64url").toString());
		expect(payload).toMatchObject({
			sub: "user-1",
			azp: CLIENT_ID,
			scope: "openid profile",
			// The client's configured resource audience, not the issuer: this
			// token is for a resource, and an audience-less token is accepted by
			// anything that checks `aud` loosely.
			aud: "https://api.example.test",
		});
	});
});

describe("code generation", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	it("re-draws when a generated code collides with a live one", async () => {
		// A collision is a generator failure, not traffic. The store refuses to
		// overwrite — which would hand the new device the old one's approval —
		// so the endpoint draws again rather than failing the caller for
		// something it did not cause.
		const { app } = makeHarness();
		const first = await startDevice(app);
		expect(first.status).toBe(200);

		const collidingCode = normaliseUserCode(first.body.user_code as string) as string;
		const spy = vi.spyOn(await import("@o3co/auth-provider-core"), "generateUserCode");
		spy.mockReturnValueOnce(first.body.user_code as string);

		const second = await startDevice(app);
		expect(second.status).toBe(200);
		expect(normaliseUserCode(second.body.user_code as string)).not.toBe(collidingCode);
		spy.mockRestore();
	});

	it("gives up after a run of collisions rather than looping", async () => {
		const { app } = makeHarness();
		const first = await startDevice(app);
		const spy = vi.spyOn(await import("@o3co/auth-provider-core"), "generateUserCode");
		spy.mockReturnValue(first.body.user_code as string);

		const second = await startDevice(app);
		expect(second.status).toBe(500);
		expect(second.body.error).toBe("server_error");
		spy.mockRestore();
	});

	it("keeps generateUserCode honest about its own normalisation", () => {
		expect(normaliseUserCode(generateUserCode())).not.toBeNull();
	});
});

describe("store capacity (#445)", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("answers 503 temporarily_unavailable for a new device at the cap, and keeps the first device's code live", async () => {
		// A flood that reaches the cap must cost the flooder, not the user
		// already mid-flow: the store refuses the newcomer instead of evicting
		// a live record, and the endpoint reports that as what RFC 6749 §5.2
		// calls "temporary overloading" rather than as a code collision.
		const { app, poll, clock } = makeHarness({
			store: createMemoryDeviceCodeStore({ maxEntries: 1 }),
		});
		const first = await startDevice(app);
		expect(first.status).toBe(200);

		const spy = vi.spyOn(await import("@o3co/auth-provider-core"), "generateUserCode");
		const second = await startDevice(app);
		expect(second.status).toBe(503);
		expect(second.body.error).toBe("temporarily_unavailable");
		expect(second.headers["cache-control"]).toContain("no-store");
		// The store refused the slot, not the code, so re-drawing cannot
		// help: one draw, not five sweeps of the map to find that out.
		expect(spy).toHaveBeenCalledTimes(1);

		clock.advance(10_000);
		expect((await poll(first.body.device_code as string)).result).toMatchObject({
			status: 400,
			error: "authorization_pending",
		});
	});
});
