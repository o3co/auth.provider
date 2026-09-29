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
 * Device verification on session admission (the session-admission ADR's D4,
 * D8, and its build-order row A4): the three actions it admits, what it
 * answers for each `Admission`, and each change against develop pinned by
 * name.
 *
 * The handler is mounted by hand, as flow.test.mts mounts it, behind a fixed
 * cookie session and the fixed `UserSession` records of `liveSessions.mts`,
 * with a resolver `resolverForTests` builds over a fixture requirement that
 * answers what a test asks and records what it was asked. With no
 * requirement registered the endpoint answers what flow.test.mts pins.
 */

import {
	createMemoryDeviceCodeStore,
	createMemoryRateLimiter,
	type RequirementInput,
	type RequirementVerdict,
	type SessionRequirement,
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createDeviceVerificationHandler } from "#/verificationEndpoint.mjs";
import { LIVE_SID, liveCookieSession, liveSessionStore } from "./liveSessions.mjs";

/** The handler's clock, and the instant each fixed session authenticated at. */
const NOW = 1_800_000_000_000;
const ISSUER = "https://as.example.test";
const USER_CODE = "BCDFGHJK";
const DEVICE_CODE = "dc-aaaaaaaaaaaaaaaaaaaa";

const settings = {
	verificationUri: "https://example.test/device",
	verificationUriComplete: false,
	codeLifetimeSeconds: 600,
	pollingIntervalSeconds: 5,
};

const ACTIONS = ["lookup", "approve", "deny"] as const;

/**
 * A requirement that answers `answer` for every input and records each one.
 * Its page is set so a `step_up` is one admission can answer; its reach is
 * empty, as any requirement's but `mfa` must be in this release.
 */
const fixture = (
	answer: (input: RequirementInput) => RequirementVerdict,
	asked: RequirementInput[] = [],
	stepUpPage: SessionRequirement["stepUpPage"] = { url: "/step-up", params: {} },
): SessionRequirement => ({
	name: "fixture",
	reach: new Set<string>(),
	stepUpPage,
	remediations: [],
	hintKeys: [],
	admit: async (input) => {
		asked.push(input);
		return answer(input);
	},
});

const makeLogger = () => ({ warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() });

interface HarnessOptions {
	readonly requirements?: readonly SessionRequirement[];
	readonly session?: Record<string, unknown>;
	readonly userSessionStore?: UserSessionStore;
	readonly subjectRevocation?: SubjectRevocation;
	readonly requireEmailVerified?: boolean;
	/** The verification budget; five, as the module seeds it, unless a test needs it spent sooner. */
	readonly limit?: number;
}

const harness = async (options: HarnessOptions = {}) => {
	const store = createMemoryDeviceCodeStore();
	await store.create({
		deviceCode: DEVICE_CODE,
		userCode: USER_CODE,
		clientId: "tv-app",
		requestedScope: ["openid"],
		expiresAtMs: NOW + 600_000,
		intervalSeconds: 5,
	});
	const logger = makeLogger();
	const app = express();
	app.use(express.json());
	app.use((req, _res, next) => {
		(req as unknown as { session: unknown }).session = options.session ?? liveCookieSession();
		next();
	});
	app.post(
		"/oauth/device/verification",
		createDeviceVerificationHandler({
			store,
			settings,
			rateLimiter: createMemoryRateLimiter({
				limits: { device_verification: { limit: options.limit ?? 5, windowSeconds: 300 } },
				defaultLimit: { limit: 60, windowSeconds: 60 },
			}),
			failMode: "closed",
			userSessionStore: options.userSessionStore ?? liveSessionStore(),
			...(options.subjectRevocation === undefined
				? {}
				: { subjectRevocation: options.subjectRevocation }),
			requirements: resolverForTests(options.requirements ?? [], { issuer: ISSUER }),
			issuer: ISSUER,
			requireEmailVerified: options.requireEmailVerified ?? false,
			now: () => NOW,
			logger,
		}),
	);
	const verify = (body: Record<string, unknown>) =>
		request(app).post("/oauth/device/verification").send(body);
	/** Whether the seeded code is still undecided. */
	const undecided = async () => (await store.findPendingByUserCode(USER_CODE, NOW)) !== null;
	/** Who the seeded code was approved by, if it was. */
	const approvedBy = async () => {
		const polled = await store.poll(DEVICE_CODE, NOW);
		return polled.status === "approved" ? polled.authorization.subject : undefined;
	};
	return { verify, undecided, approvedBy, logger };
};

/** `liveSessionStore()` with `user-1`'s record expiring at `expiresAt`. */
const expiringAt = (expiresAt: number): UserSessionStore => {
	const store = liveSessionStore();
	const get = store.get.bind(store);
	store.get = async (sid) => {
		const record = await get(sid);
		return record === null ? null : { ...record, expiresAt: new Date(expiresAt) };
	};
	return store;
};

describe("device verification on session admission (the session-admission ADR's D8)", () => {
	it("parses the body first: an action it does not implement is 400 before the 401 of a signed-out cookie and the 503 of a store outage (a pinned change)", async () => {
		const asked: RequirementInput[] = [];
		const signedOut = await harness({
			session: { isAuthenticated: false },
			requirements: [fixture(() => ({ outcome: "met" }), asked)],
		});
		for (const body of [{ action: "revoke", user_code: USER_CODE }, { user_code: USER_CODE }]) {
			const res = await signedOut.verify(body);
			expect(res.status).toBe(400);
			expect(res.body).toEqual({
				error: "invalid_request",
				error_description: "action must be one of: lookup, approve, deny",
			});
		}

		const down = liveSessionStore();
		down.get = async () => {
			throw new Error("redis down");
		};
		const outage = await harness({ userSessionStore: down });
		expect((await outage.verify({ action: "revoke", user_code: USER_CODE })).status).toBe(400);
		// Nothing was read for a body that names no action: no session, no requirement.
		expect(outage.logger.error).not.toHaveBeenCalled();
		expect(asked).toEqual([]);
	});

	it.each(ACTIONS)(
		"admits %s as its own action, device.<action>, graded use, on the cookie's claim",
		async (action) => {
			const asked: RequirementInput[] = [];
			const { verify } = await harness({
				requirements: [fixture(() => ({ outcome: "met" }), asked)],
			});
			const res = await verify({ action, user_code: USER_CODE });
			expect(res.status).toBe(200);
			expect(asked).toHaveLength(1);
			expect(asked[0]?.action).toEqual({ name: `device.${action}`, grade: "use" });
			expect(asked[0]).toMatchObject({
				carrier: "cookie",
				subject: "user-1",
				session: { sid: LIVE_SID, sub: "user-1" },
			});
		},
	);

	it("approves as the subject of the record admission read", async () => {
		const { verify, approvedBy } = await harness({
			session: { isAuthenticated: true, user: { id: "user-2" }, sid: "sid-2" },
		});
		expect((await verify({ action: "approve", user_code: USER_CODE })).status).toBe(200);
		expect(await approvedBy()).toBe("user-2");
	});

	it("answers a step-up on approve 403 step_up_required, naming the requirement, and decides nothing", async () => {
		const { verify, undecided } = await harness({
			requirements: [
				fixture(({ action }) =>
					action.name === "device.approve"
						? { outcome: "step_up", whenStillUnmet: "reauthenticate" }
						: { outcome: "met" },
				),
			],
		});
		const res = await verify({ action: "approve", user_code: USER_CODE });
		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "step_up_required",
			error_description: "the session must step up before it can do this",
			requirement: "fixture",
			// The requirement's page on the issuer (the ADR's D8): a browser-facing
			// consumer answers where the step-up starts.
			page: `${ISSUER}/step-up`,
		});
		expect(await undecided()).toBe(true);
		// The lookup the same requirement admits is answered.
		expect((await verify({ action: "lookup", user_code: USER_CODE })).status).toBe(200);
	});

	it.each(["lookup", "deny"] as const)(
		"answers a step-up another requirement asks for on %s 403 step_up_required all the same",
		async (action) => {
			const { verify, undecided } = await harness({
				requirements: [fixture(() => ({ outcome: "step_up", whenStillUnmet: "unmet" }))],
			});
			const res = await verify({ action, user_code: USER_CODE });
			expect(res.status).toBe(403);
			expect(res.body).toMatchObject({ error: "step_up_required", requirement: "fixture" });
			expect(await undecided()).toBe(true);
		},
	);

	it("refuses a step-up before the email gate, and spends none of the subject's budget on it", async () => {
		const { verify } = await harness({
			limit: 1,
			requireEmailVerified: true,
			requirements: [
				fixture(({ action }) =>
					action.name === "device.approve"
						? { outcome: "step_up", whenStillUnmet: "reauthenticate" }
						: { outcome: "met" },
				),
			],
		});
		for (let i = 0; i < 3; i++) {
			const res = await verify({ action: "approve", user_code: USER_CODE });
			expect(res.status).toBe(403);
			expect(res.body.error).toBe("step_up_required");
		}
		// The one attempt the budget holds is still there.
		expect((await verify({ action: "lookup", user_code: USER_CODE })).status).toBe(200);
	});

	it.each(["reauthenticate", "unmet"] as const)(
		"answers a requirement's %s 401 login_required: a new login is all the page can offer",
		async (outcome) => {
			for (const action of ACTIONS) {
				const { verify, undecided } = await harness({
					requirements: [fixture(() => ({ outcome }))],
				});
				const res = await verify({ action, user_code: USER_CODE });
				expect(res.status, action).toBe(401);
				expect(res.body, action).toEqual({
					error: "login_required",
					error_description: "sign in again to continue",
				});
				expect(await undecided(), action).toBe(true);
			}
		},
	);

	it("refuses a session whose expiresAt is not later than now as one that is no longer active (a pinned change)", async () => {
		// develop asked the store alone, and a store that does not filter an
		// expired record on `get` — the port does not promise it — let it approve.
		const expired = await harness({ userSessionStore: expiringAt(NOW) });
		const res = await expired.verify({ action: "approve", user_code: USER_CODE });
		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			error: "login_required",
			error_description: "the session is no longer active; sign in again",
		});
		expect(await expired.undecided()).toBe(true);

		// On the handler's clock: a millisecond later is live.
		const live = await harness({ userSessionStore: expiringAt(NOW + 1) });
		expect((await live.verify({ action: "lookup", user_code: USER_CODE })).status).toBe(200);
	});

	it("answers a cookie that names no user as it did, and warns admission's line", async () => {
		const { verify, logger } = await harness({
			session: { isAuthenticated: true, sid: LIVE_SID },
		});
		const res = await verify({ action: "lookup", user_code: USER_CODE });
		expect(res.status).toBe(401);
		expect(res.body).toEqual({
			error: "login_required",
			error_description: "an authenticated end-user session is required to approve a device",
		});
		expect(logger.warn).toHaveBeenCalledWith(
			{ action: "device.lookup" },
			"session_admission_no_subject",
		);
	});

	it("answers a requirement that throws 503, logged once at error by admission with the requirement's name", async () => {
		const { verify, logger, undecided } = await harness({
			requirements: [
				fixture(() => {
					throw new Error("risk engine down");
				}),
			],
		});
		const res = await verify({ action: "approve", user_code: USER_CODE });
		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "session requirement unavailable",
		});
		expect(logger.error).toHaveBeenCalledTimes(1);
		const [line, event] = logger.error.mock.calls[0] as [Record<string, unknown>, string];
		expect(event).toBe("session_admission_unavailable");
		expect(line).toMatchObject({ store: "fixture", action: "device.approve" });
		expect(await undecided()).toBe(true);
	});

	it("describes each outage by what could not answer — the session store, the revocation boundary's store, a requirement — never a requirement's as the session store's", async () => {
		const storeDown = {
			...liveSessionStore(),
			get: async () => {
				throw new Error("session store down");
			},
		} as UserSessionStore;
		const boundaryDown: SubjectRevocation = {
			kind: "test",
			revokeBefore: async () => undefined,
			revokedBefore: async () => {
				throw new Error("boundary down");
			},
		} as unknown as SubjectRevocation;
		const requirementDown = fixture(() => {
			throw new Error("risk engine down");
		});
		for (const [options, description] of [
			[{ userSessionStore: storeDown }, "session store unavailable"],
			[{ subjectRevocation: boundaryDown }, "revocation store unavailable"],
			[{ requirements: [requirementDown] }, "session requirement unavailable"],
		] as const) {
			const { verify } = await harness(options as HarnessOptions);
			const res = await verify({ action: "lookup", user_code: USER_CODE });
			expect(res.status, description).toBe(503);
			expect(res.body, description).toEqual({
				error: "temporarily_unavailable",
				error_description: description,
			});
		}
	});

	it("reads no session twice and no boundary itself: one admission per request", async () => {
		const store = liveSessionStore();
		const get = vi.fn(store.get.bind(store));
		store.get = get;
		const { verify } = await harness({ userSessionStore: store });
		expect((await verify({ action: "approve", user_code: USER_CODE })).status).toBe(200);
		expect(get).toHaveBeenCalledTimes(1);
		expect(get).toHaveBeenCalledWith(LIVE_SID);
	});

	it.each([
		[
			"a path, with its params",
			{ url: "/mfa/step-up", params: { flow: "device", ui: "compact" } },
			`${ISSUER}/mfa/step-up?flow=device&ui=compact`,
		],
		[
			"an absolute URL on the issuer, its own query kept",
			{ url: `${ISSUER}/mfa?x=1`, params: { flow: "device" } },
			`${ISSUER}/mfa?x=1&flow=device`,
		],
	] as const)(
		"answers the step-up page as an absolute URL on the issuer — %s — with no return parameter",
		async (_label, stepUpPage, page) => {
			const { verify } = await harness({
				requirements: [
					fixture(() => ({ outcome: "step_up", whenStillUnmet: "reauthenticate" }), [], stepUpPage),
				],
			});
			const res = await verify({ action: "approve", user_code: USER_CODE });
			expect(res.status).toBe(403);
			expect(res.body.page).toBe(page);
			expect(new URL(res.body.page as string).searchParams.has("redirect_to")).toBe(false);
		},
	);

	it("refuses to be built with a resolver the planner did not build: a forged one is a build error, not a 500 per request", () => {
		const forged = { get: () => undefined, entries: () => [][Symbol.iterator]() };
		expect(() =>
			createDeviceVerificationHandler({
				store: createMemoryDeviceCodeStore(),
				settings,
				rateLimiter: createMemoryRateLimiter({
					limits: { device_verification: { limit: 5, windowSeconds: 300 } },
					defaultLimit: { limit: 60, windowSeconds: 60 },
				}),
				failMode: "closed",
				userSessionStore: liveSessionStore(),
				requirements: forged,
				issuer: ISSUER,
				requireEmailVerified: false,
			} as never),
		).toThrow(/sessionRequirementResolver the boot planner built/);
	});

	it("refuses to be built without an issuer to resolve a step-up page on", () => {
		for (const issuer of [undefined, "", "not a url"]) {
			expect(
				() =>
					createDeviceVerificationHandler({
						store: createMemoryDeviceCodeStore(),
						settings,
						rateLimiter: createMemoryRateLimiter({
							limits: { device_verification: { limit: 5, windowSeconds: 300 } },
							defaultLimit: { limit: 60, windowSeconds: 60 },
						}),
						failMode: "closed",
						userSessionStore: liveSessionStore(),
						requirements: resolverForTests([]),
						...(issuer === undefined ? {} : { issuer }),
						requireEmailVerified: false,
					} as never),
				String(issuer),
			).toThrow(/issuer/);
		}
	});

	it("refuses to be built on an issuer that is not an absolute http(s) URL: a step-up page resolved on mailto:, urn: or data: throws, a 500 where step_up_required belongs", () => {
		for (const issuer of [
			"mailto:admin@example.com",
			"urn:example:issuer",
			"data:text/plain,issuer",
			"as.example.test/relative",
			"/relative",
		]) {
			expect(
				() =>
					createDeviceVerificationHandler({
						store: createMemoryDeviceCodeStore(),
						settings,
						rateLimiter: createMemoryRateLimiter({
							limits: { device_verification: { limit: 5, windowSeconds: 300 } },
							defaultLimit: { limit: 60, windowSeconds: 60 },
						}),
						failMode: "closed",
						userSessionStore: liveSessionStore(),
						requirements: resolverForTests([]),
						issuer,
						requireEmailVerified: false,
					}),
				issuer,
			).toThrow(/issuer/);
		}
	});

	it("refuses to be built without requirements, as it refuses to be built without a store", () => {
		expect(() =>
			createDeviceVerificationHandler({
				store: createMemoryDeviceCodeStore(),
				settings,
				rateLimiter: createMemoryRateLimiter({
					limits: { device_verification: { limit: 5, windowSeconds: 300 } },
					defaultLimit: { limit: 60, windowSeconds: 60 },
				}),
				failMode: "closed",
				userSessionStore: liveSessionStore(),
				requireEmailVerified: false,
			} as never),
		).toThrow(/requirements/);
	});
});
