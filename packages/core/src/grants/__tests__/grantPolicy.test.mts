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

import { describe, expect, it, vi } from "vitest";
import {
	boundPolicyAudience,
	evaluateGrantPolicy,
	policyDenied,
	policyOutOfBounds,
	policyUnavailable,
	readGrantPolicyDecision,
} from "#/grants/grantPolicy.mjs";
import { consoleLogger } from "#/logging/consoleLogger.mjs";
import type {
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyHook,
	GrantPolicyRequest,
} from "#/policy/types.mjs";

/**
 * The one answer every minting path gives a policy that throws, denies, or
 * exceeds its ceiling.
 */

const hook = (decide: () => Promise<GrantPolicyDecision>): GrantPolicyHook => ({
	kind: "stub",
	evaluate: decide,
});
const kindHook = (kind: string, decide: () => Promise<GrantPolicyDecision>): GrantPolicyHook => ({
	kind,
	evaluate: decide,
});
const allow = (extra: Partial<Extract<GrantPolicyDecision, { outcome: "allow" }>> = {}) =>
	hook(async () => ({ outcome: "allow", ...extra }));

/**
 * What a JavaScript policy can return that is neither an exact `allow` nor an
 * exact `deny`.
 */
const INVALID_DECISIONS: ReadonlyArray<readonly [string, unknown]> = [
	["another outcome", { outcome: "denied", error: "access_denied" }],
	["another case", { outcome: "Deny" }],
	["no outcome", {}],
	["null", null],
	["a bare string", "allow"],
	["a String object", new String("allow")],
	["an array", ["allow"]],
	[
		"an outcome that throws when read",
		Object.defineProperty({}, "outcome", {
			get() {
				throw new Error("unreadable");
			},
		}),
	],
];

/** What an invalid decision is answered with, whatever it held. */
const DECISION_INVALID = {
	status: 500,
	error: "server_error",
	errorDescription: "policy_decision_invalid",
};

const request: GrantPolicyRequest = {
	grantType: "test",
	clientId: "app",
	subject: "u-1",
	requestedScope: ["read"],
};
const context: GrantPolicyContext = { issuer: "https://auth.test" };

describe("policyOutOfBounds", () => {
	it("is 500 server_error carrying the description", () => {
		// The caller did nothing wrong; the deployment's policy did. A 4xx would
		// send the wrong person looking and hide the fault from 5xx alerting.
		expect(policyOutOfBounds("policy returned x")).toEqual({
			status: 500,
			error: "server_error",
			errorDescription: "policy returned x",
		});
	});
});

describe("policyUnavailable", () => {
	it("is 503 temporarily_unavailable with the fixed description", () => {
		expect(policyUnavailable()).toEqual({
			status: 503,
			error: "temporarily_unavailable",
			errorDescription: "policy evaluation unavailable",
		});
	});
});

describe("evaluateGrantPolicy", () => {
	it("answers a policy that throws with policyUnavailable", async () => {
		const outcome = await evaluateGrantPolicy(
			hook(async () => {
				throw new Error("policy service down");
			}),
			request,
			context,
			["read"],
			{ logger: { error: vi.fn() } },
		);
		expect(outcome).toEqual({ ok: false, result: policyUnavailable() });
	});

	it("answers 503 temporarily_unavailable when the policy throws — fail closed, never open", async () => {
		const logger = { error: vi.fn() };
		const outcome = await evaluateGrantPolicy(
			hook(async () => {
				throw new Error("policy service down");
			}),
			request,
			context,
			["read"],
			{ logger },
		);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "policy evaluation unavailable",
			},
		});
		// Logged once through the logger the caller had to name.
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({
				grantType: request.grantType,
				err: expect.objectContaining({ name: "Error" }),
			}),
			"grant_policy_unavailable",
		);
	});

	it.each(INVALID_DECISIONS)(
		"refuses a decision with %s as 500 server_error and logs it, never allowing it",
		async (_label, decision) => {
			const logger = { error: vi.fn() };
			const outcome = await evaluateGrantPolicy(
				hook(async () => decision as GrantPolicyDecision),
				request,
				context,
				["read"],
				{ logger },
			);
			expect(outcome).toEqual({ ok: false, result: DECISION_INVALID });
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(
				{ grantType: request.grantType, policy: "stub" },
				"grant_policy_decision_invalid",
			);
		},
	);

	// A composition that wires no logger leaves the grant's `undefined`; the
	// policy's two lines still reach core's console logger.
	it("writes a throwing policy's line to core's console logger when the grant has no logger", async () => {
		const spy = vi.spyOn(consoleLogger, "error").mockImplementation(() => {});
		try {
			const outcome = await evaluateGrantPolicy(
				hook(async () => {
					throw new Error("policy service down");
				}),
				request,
				context,
				["read"],
				{ logger: undefined },
			);
			expect(outcome).toMatchObject({ ok: false, result: { status: 503 } });
			expect(spy.mock.calls.map(([, event]) => event)).toEqual(["grant_policy_unavailable"]);
		} finally {
			spy.mockRestore();
		}
	});

	it("writes an invalid decision's line to core's console logger when the grant has no logger", async () => {
		const spy = vi.spyOn(consoleLogger, "error").mockImplementation(() => {});
		try {
			const outcome = await evaluateGrantPolicy(
				hook(async () => ({ outcome: "denied" }) as unknown as GrantPolicyDecision),
				request,
				context,
				["read"],
				{ logger: undefined },
			);
			expect(outcome).toEqual({ ok: false, result: DECISION_INVALID });
			expect(spy.mock.calls).toEqual([
				[{ grantType: request.grantType, policy: "stub" }, "grant_policy_decision_invalid"],
			]);
		} finally {
			spy.mockRestore();
		}
	});

	it("passes a deny with a token-endpoint code through as 400 with the policy's own error, marked as the policy's", async () => {
		const logger = { error: vi.fn(), warn: vi.fn() };
		const outcome = await evaluateGrantPolicy(
			hook(async () => ({
				outcome: "deny",
				error: "invalid_scope",
				errorDescription: "not today",
			})),
			request,
			context,
			["read"],
			{ logger },
		);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 400,
				error: "invalid_scope",
				errorDescription: "not today",
				policyDenial: { error: "invalid_scope" },
			},
		});
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("answers a deny whose code the token endpoint does not define invalid_request, not invalid_grant, logged at warn", async () => {
		// `invalid_grant` would tell a client its grant is dead: an SDK
		// discards its refresh token on it.
		const logger = { error: vi.fn(), warn: vi.fn() };
		const outcome = await evaluateGrantPolicy(
			kindHook("evaluate-default", async () => ({
				outcome: "deny",
				error: "access_denied",
				errorDescription: "not today",
			})),
			request,
			context,
			["read"],
			{ logger },
		);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 400,
				error: "invalid_request",
				errorDescription: "not today",
				policyDenial: { error: "access_denied" },
			},
		});
		expect(logger.warn.mock.calls).toEqual([
			[
				{
					grantType: request.grantType,
					policy: "evaluate-default",
					error: "access_denied",
					answered: "invalid_request",
				},
				"grant_policy_refusal_rewritten",
			],
		]);
	});

	it("answers such a deny with the grant's denyFallback when it names one", async () => {
		const outcome = await evaluateGrantPolicy(
			kindHook("evaluate-fallback", async () => ({ outcome: "deny", error: "consent_required" })),
			request,
			context,
			["read"],
			{ logger: { error: vi.fn(), warn: vi.fn() }, denyFallback: "invalid_grant" },
		);
		expect(outcome).toMatchObject({ ok: false, result: { status: 400, error: "invalid_grant" } });
	});

	it("passes a code the grant's denyAllowed names through, but never an RFC 8628 code that says keep polling", async () => {
		const answer = async (error: string) => {
			const outcome = await evaluateGrantPolicy(
				kindHook("evaluate-allowed", async () => ({ outcome: "deny", error })),
				request,
				context,
				["read"],
				{
					logger: { error: vi.fn(), warn: vi.fn() },
					denyFallback: "invalid_grant",
					denyAllowed: ["access_denied", "expired_token", "authorization_pending", "slow_down"],
				},
			);
			return !outcome.ok && outcome.result.error;
		};
		expect(await answer("access_denied")).toBe("access_denied");
		expect(await answer("expired_token")).toBe("expired_token");
		expect(await answer("authorization_pending")).toBe("invalid_grant");
		expect(await answer("slow_down")).toBe("invalid_grant");
	});

	it("writes the rewrite line to core's console logger when the caller's logger has no warn", async () => {
		const spy = vi.spyOn(consoleLogger, "warn").mockImplementation(() => {});
		try {
			const outcome = await evaluateGrantPolicy(
				kindHook("evaluate-console", async () => ({ outcome: "deny", error: "slow_down" })),
				request,
				context,
				["read"],
				{ logger: { error: vi.fn() } },
			);
			expect(outcome).toMatchObject({
				ok: false,
				result: { status: 400, error: "invalid_request" },
			});
			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0]?.[1]).toBe("grant_policy_refusal_rewritten");
		} finally {
			spy.mockRestore();
		}
	});

	it("leaves the effective scope alone when the policy says nothing about it", async () => {
		const outcome = await evaluateGrantPolicy(allow(), request, context, ["read", "write"], {
			logger: undefined,
		});
		expect(outcome).toMatchObject({ ok: true, scopes: ["read", "write"] });
	});

	it("narrows to what the policy grants, and honours an empty array as strip-all", async () => {
		expect(
			await evaluateGrantPolicy(
				allow({ grantedScope: ["read"] }),
				request,
				context,
				["read", "write"],
				{ logger: undefined },
			),
		).toMatchObject({ ok: true, scopes: ["read"] });
		expect(
			await evaluateGrantPolicy(allow({ grantedScope: [] }), request, context, ["read"], {
				logger: undefined,
			}),
		).toMatchObject({ ok: true, scopes: [] });
	});

	it("refuses a policy that widens past the effective scope as 500 server_error naming the extra", async () => {
		const outcome = await evaluateGrantPolicy(
			allow({ grantedScope: ["read", "admin"] }),
			request,
			context,
			["read"],
			{ logger: undefined },
		);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 500,
				error: "server_error",
				errorDescription: "policy returned scopes exceeding requested scope: admin",
			},
		});
	});

	it("bounds the grant against a ceiling wider than the default when the grant has one", async () => {
		// `refresh_token`'s ceiling is the original grant (RFC 6749 §6), and its
		// default the narrower scope the refresh asked for. The home took one
		// list for both, so the refresh grant carried its own copy of this whole
		// function — the copy the drift guard could not see.
		const ceiling = { scopes: ["read", "write"], name: "original grant" };
		const within = await evaluateGrantPolicy(
			allow({ grantedScope: ["read", "write"] }),
			request,
			context,
			["read"],
			{ scopeCeiling: ceiling, logger: undefined },
		);
		expect(within).toMatchObject({ ok: true, scopes: ["read", "write"] });

		const beyond = await evaluateGrantPolicy(
			allow({ grantedScope: ["read", "admin"] }),
			request,
			context,
			["read"],
			{ scopeCeiling: ceiling, logger: undefined },
		);
		expect(beyond).toEqual({
			ok: false,
			result: {
				status: 500,
				error: "server_error",
				errorDescription: "policy returned scopes exceeding original grant: admin",
			},
		});

		// Silent, the default stands — not the ceiling.
		expect(
			await evaluateGrantPolicy(allow(), request, context, ["read"], {
				scopeCeiling: ceiling,
				logger: undefined,
			}),
		).toMatchObject({
			ok: true,
			scopes: ["read"],
		});
	});

	it("hands the allow decision back so the caller can bound its audience", async () => {
		const outcome = await evaluateGrantPolicy(
			allow({ grantedAudience: ["https://api.example"] }),
			request,
			context,
			["read"],
			{ logger: undefined },
		);
		expect(outcome.ok && outcome.decision.grantedAudience).toEqual(["https://api.example"]);
	});

	it("reads grantedScope once, so a getter that widens on a later read gets what it first answered", async () => {
		let reads = 0;
		const decision = {
			outcome: "allow",
			get grantedScope() {
				reads += 1;
				return reads === 1 ? ["read"] : ["read", "admin"];
			},
		};
		const outcome = await evaluateGrantPolicy(
			hook(async () => decision as GrantPolicyDecision),
			request,
			context,
			["read"],
			{ logger: undefined },
		);
		expect(outcome).toMatchObject({ ok: true, scopes: ["read"] });
		expect(reads).toBe(1);
	});

	it("refuses a grantedScope with a hole in it as 500 server_error", async () => {
		const grantedScope: string[] = [];
		grantedScope[1] = "read";
		const outcome = await evaluateGrantPolicy(allow({ grantedScope }), request, context, ["read"], {
			logger: undefined,
		});
		expect(outcome).toMatchObject({ ok: false, result: { status: 500, error: "server_error" } });
	});

	it("refuses a non-array grantedScope as 500 server_error instead of throwing", async () => {
		// A JS policy returning a string passes a truthiness check, and
		// `.filter` then throws a TypeError that /token dispatch does not
		// catch — fail-closed, but ungraceful.
		const outcome = await evaluateGrantPolicy(
			allow({ grantedScope: "read" as unknown as readonly string[] }),
			request,
			context,
			["read"],
			{ logger: undefined },
		);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 500,
				error: "server_error",
				errorDescription: "policy returned a non-array grantedScope",
			},
		});
	});
});

describe("readGrantPolicyDecision", () => {
	const site = { grantType: "test", policy: "stub" };

	it("reads an exact allow and an exact deny as themselves, logging nothing", () => {
		const logger = { error: vi.fn() };
		const allowed = { outcome: "allow", grantedScope: ["read"] } as const;
		const denied = { outcome: "deny", error: "access_denied" } as const;
		expect(readGrantPolicyDecision(allowed, logger, site)).toEqual({
			verdict: "allow",
			decision: allowed,
		});
		expect(readGrantPolicyDecision(denied, logger, site)).toEqual({
			verdict: "deny",
			decision: denied,
		});
		expect(logger.error).not.toHaveBeenCalled();
	});

	it.each(INVALID_DECISIONS)(
		"reads a decision with %s as invalid, logging the policy and not the decision",
		(_label, decision) => {
			const logger = { error: vi.fn() };
			expect(readGrantPolicyDecision(decision, logger, site)).toEqual({
				verdict: "invalid",
				result: DECISION_INVALID,
			});
			expect(logger.error).toHaveBeenCalledTimes(1);
			expect(logger.error).toHaveBeenCalledWith(site, "grant_policy_decision_invalid");
		},
	);

	it("reads outcome once, so a getter that answers allow and then deny is allowed", () => {
		let reads = 0;
		const decision = {
			get outcome() {
				reads += 1;
				return reads === 1 ? "allow" : "deny";
			},
		};
		expect(readGrantPolicyDecision(decision, { error: vi.fn() }, site)).toMatchObject({
			verdict: "allow",
		});
		expect(reads).toBe(1);
	});

	it("reads each field of an allow once, into a plain copy", () => {
		const reads: string[] = [];
		const grantedScope = ["read"];
		const grantedAudience = ["https://api.example"];
		const answer = new Proxy(
			{ outcome: "allow", grantedScope, grantedAudience },
			{
				get(target, key, receiver) {
					reads.push(String(key));
					return Reflect.get(target, key, receiver);
				},
			},
		);
		const reading = readGrantPolicyDecision(answer, { error: vi.fn() }, site);
		expect(reads.toSorted()).toEqual(["grantedAudience", "grantedScope", "outcome"]);
		expect(reading).toStrictEqual({
			verdict: "allow",
			decision: {
				outcome: "allow",
				grantedScope: ["read"],
				grantedAudience: ["https://api.example"],
			},
		});
		const { decision } = reading as Extract<typeof reading, { verdict: "allow" }>;
		expect(decision).not.toBe(answer);
		expect(decision.grantedScope).not.toBe(grantedScope);
		expect(decision.grantedAudience).not.toBe(grantedAudience);
	});

	it("keeps the copy of an allow's arrays when the policy changes its own arrays afterwards", () => {
		const grantedScope = ["read"];
		const grantedAudience = ["https://api.example"];
		const reading = readGrantPolicyDecision(
			{ outcome: "allow", grantedScope, grantedAudience },
			{ error: vi.fn() },
			site,
		);
		grantedScope.push("admin");
		grantedAudience.push("https://evil.example");
		expect(reading).toEqual({
			verdict: "allow",
			decision: {
				outcome: "allow",
				grantedScope: ["read"],
				grantedAudience: ["https://api.example"],
			},
		});
	});

	it("reads each field of a deny once, into a plain copy", () => {
		const reads: string[] = [];
		const answer = new Proxy(
			{ outcome: "deny", error: "access_denied", errorDescription: "not today" },
			{
				get(target, key, receiver) {
					reads.push(String(key));
					return Reflect.get(target, key, receiver);
				},
			},
		);
		const reading = readGrantPolicyDecision(answer, { error: vi.fn() }, site);
		expect(reads.toSorted()).toEqual(["error", "errorDescription", "outcome"]);
		expect(reading).toStrictEqual({
			verdict: "deny",
			decision: { outcome: "deny", error: "access_denied", errorDescription: "not today" },
		});
		expect((reading as Extract<typeof reading, { verdict: "deny" }>).decision).not.toBe(answer);
	});

	it.each([
		["an allow's grantedScope", { outcome: "allow" }, "grantedScope"],
		["an allow's grantedAudience", { outcome: "allow" }, "grantedAudience"],
		["a deny's error", { outcome: "deny" }, "error"],
		["a deny's errorDescription", { outcome: "deny", error: "access_denied" }, "errorDescription"],
	] as const)("reads a decision as invalid when %s throws when read", (_label, fields, key) => {
		const decision = Object.defineProperty({ ...fields }, key, {
			get() {
				throw new Error("unreadable");
			},
		});
		const logger = { error: vi.fn() };
		expect(readGrantPolicyDecision(decision, logger, site)).toEqual({
			verdict: "invalid",
			result: DECISION_INVALID,
		});
		expect(logger.error).toHaveBeenCalledWith(site, "grant_policy_decision_invalid");
	});

	it.each([
		["a Symbol", Symbol("scope")],
		["an object with no prototype", Object.create(null)],
		[
			"an object whose toString throws",
			{
				toString: () => {
					throw new Error("no");
				},
			},
		],
		["a number", 7],
		["undefined", undefined],
	])(
		"reads an allow whose granted elements include %s as invalid, without throwing",
		(_label, value) => {
			for (const field of ["grantedScope", "grantedAudience"]) {
				const logger = { error: vi.fn() };
				const decision = { outcome: "allow", [field]: ["read", value] };
				expect(() => readGrantPolicyDecision(decision, logger, site)).not.toThrow();
				expect(readGrantPolicyDecision(decision, logger, site), field).toEqual({
					verdict: "invalid",
					result: DECISION_INVALID,
				});
				expect(logger.error).toHaveBeenCalledWith(site, "grant_policy_decision_invalid");
			}
		},
	);

	it("reads each element of a granted array once, and judges the copy", () => {
		let reads = 0;
		const grantedScope = new Proxy(["read", "write"], {
			get(target, key, receiver) {
				if (key === "1") {
					reads += 1;
					return reads === 1 ? "write" : Symbol("later");
				}
				return Reflect.get(target, key, receiver);
			},
		});
		const reading = readGrantPolicyDecision(
			{ outcome: "allow", grantedScope },
			{ error: vi.fn() },
			site,
		);
		expect(reading).toEqual({
			verdict: "allow",
			decision: { outcome: "allow", grantedScope: ["read", "write"] },
		});
		expect(reads).toBe(1);
	});

	it("names the caller's site in the log line when it has one", () => {
		const logger = { error: vi.fn() };
		readGrantPolicyDecision({}, logger, { ...site, site: "authorize" });
		expect(logger.error).toHaveBeenCalledWith(
			{ site: "authorize", grantType: "test", policy: "stub" },
			"grant_policy_decision_invalid",
		);
	});

	it("writes an invalid decision's line to core's console logger when it is given no logger", () => {
		const spy = vi.spyOn(consoleLogger, "error").mockImplementation(() => {});
		try {
			expect(readGrantPolicyDecision({}, undefined, site)).toEqual({
				verdict: "invalid",
				result: DECISION_INVALID,
			});
			expect(spy.mock.calls).toEqual([[site, "grant_policy_decision_invalid"]]);
		} finally {
			spy.mockRestore();
		}
	});
});

describe("boundPolicyAudience", () => {
	const decision = (grantedAudience?: readonly string[]) =>
		({ outcome: "allow", ...(grantedAudience ? { grantedAudience } : {}) }) as const;

	it("treats no audience, or an empty one, as no decision", () => {
		expect(boundPolicyAudience(decision(), ["https://api.example"])).toEqual({
			ok: true,
			audience: null,
		});
		expect(boundPolicyAudience(decision([]), undefined)).toEqual({ ok: true, audience: null });
	});

	it("refuses an audience when nothing supplies a ceiling", () => {
		// No authenticated client, no `allowedAudiences`: policy may narrow,
		// never originate, and there is nothing here to narrow within.
		const outcome = boundPolicyAudience(decision(["https://api.example"]), undefined);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 500,
				error: "server_error",
				errorDescription:
					"policy returned an audience but no authenticated client supplies an allowedAudiences ceiling",
			},
		});
	});

	it("refuses an entry outside the ceiling, naming it — an empty ceiling admits nothing", () => {
		expect(
			boundPolicyAudience(decision(["https://api.example", "https://evil.example"]), [
				"https://api.example",
			]),
		).toEqual({
			ok: false,
			result: {
				status: 500,
				error: "server_error",
				errorDescription:
					"policy returned audiences outside client allowedAudiences: https://evil.example",
			},
		});
		expect(boundPolicyAudience(decision(["https://api.example"]), [])).toMatchObject({
			ok: false,
			result: { status: 500, error: "server_error" },
		});
	});

	it("takes the first entry when every entry is within the ceiling", () => {
		expect(
			boundPolicyAudience(decision(["https://other.example", "https://api.example"]), [
				"https://api.example",
				"https://other.example",
			]),
		).toEqual({ ok: true, audience: "https://other.example" });
	});

	it("refuses a non-array grantedAudience as 500 server_error instead of throwing", () => {
		const outcome = boundPolicyAudience(
			{
				outcome: "allow",
				grantedAudience: "https://api.example" as unknown as readonly string[],
			},
			["https://api.example"],
		);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 500,
				error: "server_error",
				errorDescription: "policy returned a non-array grantedAudience",
			},
		});
	});
});

describe("policyDenied", () => {
	const hookOf = (kind = "stub"): GrantPolicyHook => ({
		kind,
		evaluate: async () => ({ outcome: "allow" }),
	});
	/** A fresh policy instance, so what one test logged is not another's. */
	const fresh = (grantType = "test") => ({ grantType, hook: hookOf() });
	const logged = (site: { grantType: string; site?: string }, error: string, answered: string) => ({
		...(site.site !== undefined ? { site: site.site } : {}),
		grantType: site.grantType,
		policy: "stub",
		error,
		answered,
	});
	const deny = (error: unknown, errorDescription?: unknown) =>
		readGrantPolicyDecision(
			{ outcome: "deny", error, ...(errorDescription !== undefined ? { errorDescription } : {}) },
			{ error: vi.fn() },
			{ grantType: "test", policy: "stub" },
		) as Extract<ReturnType<typeof readGrantPolicyDecision>, { verdict: "deny" }>;

	it.each([
		"invalid_request",
		"invalid_grant",
		"unauthorized_client",
		"unsupported_grant_type",
		"invalid_scope",
		"invalid_target",
	])("answers the token-endpoint code %s as itself, logging nothing", (code) => {
		const logger = { warn: vi.fn() };
		expect(policyDenied(deny(code, "no"), logger, fresh())).toEqual({
			status: 400,
			error: code,
			errorDescription: "no",
			policyDenial: { error: code },
		});
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it.each([
		["access_denied", "access_denied"],
		["the RFC 8628 polling code authorization_pending", "authorization_pending"],
		["the RFC 8628 polling code slow_down", "slow_down"],
		["the RFC 8628 polling code expired_token", "expired_token"],
		["another extension code", "consent_required"],
		[
			"invalid_client, which RFC 6749 §5.2 answers 401 with a challenge for a client that authenticated by header",
			"invalid_client",
		],
		["a code that differs only in case", "Invalid_Grant"],
	])("answers %s invalid_request by default, logging the policy's code", (_label, code) => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		expect(policyDenied(deny(code), logger, site)).toEqual({
			status: 400,
			error: "invalid_request",
			policyDenial: { error: code },
		});
		expect(logger.warn.mock.calls).toEqual([
			[logged(site, code, "invalid_request"), "grant_policy_refusal_rewritten"],
		]);
	});

	it("answers the caller's own fallback for a code outside the set", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		expect(
			policyDenied(deny("access_denied"), logger, { ...site, fallback: "invalid_grant" }),
		).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(logger.warn).toHaveBeenCalledWith(
			logged(site, "access_denied", "invalid_grant"),
			"grant_policy_refusal_rewritten",
		);
	});

	it("passes the codes the caller allows besides the token endpoint's, except RFC 8628's keep-polling codes", () => {
		const allowed = ["access_denied", "expired_token", "authorization_pending", "slow_down"];
		const answer = (code: string) =>
			policyDenied(
				deny(code),
				{ warn: vi.fn() },
				{ ...fresh(), allowed, fallback: "invalid_grant" },
			).error;
		expect(answer("access_denied")).toBe("access_denied");
		expect(answer("expired_token")).toBe("expired_token");
		expect(answer("authorization_pending")).toBe("invalid_grant");
		expect(answer("slow_down")).toBe("invalid_grant");
		expect(answer("consent_required")).toBe("invalid_grant");
	});

	it("logs a malformed code sanitised and capped, exactly as the audit stream records client text", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		const result = policyDenied(deny(`bad"code\n\u0007${"x".repeat(300)}`), logger, site);
		const recorded = `bad?code??${"x".repeat(187)}...`;
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			policyDenial: { error: recorded },
		});
		expect(logger.warn.mock.calls).toEqual([
			[logged(site, recorded, "invalid_request"), "grant_policy_refusal_rewritten"],
		]);
	});

	it.each([
		["a number", 42, "(number)"],
		["no code", undefined, "(undefined)"],
		["the empty string", "", ""],
	])("answers %s as the code invalid_request, logging its type", (_label, code, recorded) => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		expect(policyDenied(deny(code), logger, site)).toEqual({
			status: 400,
			error: "invalid_request",
			policyDenial: { error: recorded },
		});
		expect(logger.warn).toHaveBeenCalledWith(
			logged(site, recorded, "invalid_request"),
			"grant_policy_refusal_rewritten",
		);
	});

	it("logs a policy's rewritten code once, however often it denies with it", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		for (let i = 0; i < 5; i += 1) policyDenied(deny("access_denied"), logger, site);
		policyDenied(deny("slow_down"), logger, site);
		expect(logger.warn.mock.calls.map(([fields]) => fields.error)).toEqual([
			"access_denied",
			"slow_down",
		]);
	});

	it("tells apart codes that sanitise or cap to the same text", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		const long = "x".repeat(300);
		policyDenied(deny('bad"code'), logger, site);
		policyDenied(deny("bad\\code"), logger, site);
		policyDenied(deny(`${long}a`), logger, site);
		policyDenied(deny(`${long}b`), logger, site);
		expect(logger.warn.mock.calls.map(([fields]) => fields.error)).toEqual([
			"bad?code",
			"bad?code",
			`${"x".repeat(197)}...`,
			`${"x".repeat(197)}...`,
		]);
	});

	it("logs the same code again for another grant type, site or answer", () => {
		const logger = { warn: vi.fn() };
		const hook = hookOf();
		policyDenied(deny("access_denied"), logger, { grantType: "refresh_token", hook });
		policyDenied(deny("access_denied"), logger, { grantType: "device_code", hook });
		policyDenied(deny("access_denied"), logger, {
			grantType: "device_code",
			hook,
			site: "elsewhere",
		});
		policyDenied(deny("access_denied"), logger, {
			grantType: "device_code",
			hook,
			fallback: "invalid_grant",
		});
		policyDenied(deny("access_denied"), logger, { grantType: "device_code", hook });
		expect(
			logger.warn.mock.calls.map(([fields]) => [fields.grantType, fields.site, fields.answered]),
		).toEqual([
			["refresh_token", undefined, "invalid_request"],
			["device_code", undefined, "invalid_request"],
			["device_code", "elsewhere", "invalid_request"],
			["device_code", undefined, "invalid_grant"],
		]);
	});

	it("keeps each policy instance's memory its own, even under the same kind", () => {
		const logger = { warn: vi.fn() };
		policyDenied(deny("access_denied"), logger, { grantType: "test", hook: hookOf("shared") });
		policyDenied(deny("access_denied"), logger, { grantType: "test", hook: hookOf("shared") });
		expect(logger.warn).toHaveBeenCalledTimes(2);
	});

	it("does not spend the line on the console fallback: the caller's own logger still gets it", () => {
		const spy = vi.spyOn(consoleLogger, "warn").mockImplementation(() => {});
		try {
			const site = fresh();
			policyDenied(deny("access_denied"), {}, site);
			policyDenied(deny("access_denied"), undefined, site);
			const logger = { warn: vi.fn() };
			policyDenied(deny("access_denied"), logger, site);
			policyDenied(deny("access_denied"), logger, site);
			expect(spy).toHaveBeenCalledTimes(2);
			expect(logger.warn).toHaveBeenCalledTimes(1);
		} finally {
			spy.mockRestore();
		}
	});

	it("keeps logging, with bounded memory, a policy whose codes never repeat", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		for (let i = 0; i < 3000; i += 1) policyDenied(deny(`code_${i}`), logger, site);
		expect(logger.warn).toHaveBeenCalledTimes(3000);
		// Past what it remembers it starts over: an early code is logged again.
		policyDenied(deny("code_0"), logger, site);
		expect(logger.warn).toHaveBeenCalledTimes(3001);
	});

	it.each([
		["a double quote", 'say "no"', "say ?no?"],
		["a backslash", "C:\\path", "C:?path"],
		["a line break", "line\nbreak", "line?break"],
		["a non-ASCII character", "refusé", "refus?"],
		["a control character", "bell\u0007", "bell?"],
	])(
		"repairs a description carrying %s, as every /oauth/token description is",
		(_label, text, sent) => {
			const logger = { warn: vi.fn() };
			expect(policyDenied(deny("invalid_scope", text), logger, fresh())).toMatchObject({
				status: 400,
				error: "invalid_scope",
				errorDescription: sent,
			});
			expect(logger.warn).not.toHaveBeenCalled();
		},
	);

	it("caps a description at the length the audit stream keeps", () => {
		expect(
			policyDenied(deny("invalid_scope", "y".repeat(300)), { warn: vi.fn() }, fresh())
				.errorDescription,
		).toBe(`${"y".repeat(197)}...`);
	});

	it.each([
		["the empty string", ""],
		["a number", 42],
	])("sends no description for %s, as one that is absent", (_label, text) => {
		expect(policyDenied(deny("invalid_scope", text), { warn: vi.fn() }, fresh())).toEqual({
			status: 400,
			error: "invalid_scope",
			policyDenial: { error: "invalid_scope" },
		});
	});

	it("keeps every character RFC 6749 §5.2 allows in a description", () => {
		const allowed = Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i))
			.filter((c) => c !== '"' && c !== "\\")
			.join("");
		expect(
			policyDenied(deny("invalid_scope", allowed), { warn: vi.fn() }, fresh()).errorDescription,
		).toBe(allowed);
	});

	it("names the caller's site on the line when it has one", () => {
		const logger = { warn: vi.fn() };
		const site = { ...fresh(), site: "elsewhere" };
		policyDenied(deny("access_denied"), logger, site);
		expect(logger.warn).toHaveBeenCalledWith(
			logged(site, "access_denied", "invalid_request"),
			"grant_policy_refusal_rewritten",
		);
	});
});
