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

	it("passes a deny with a token-endpoint code through as 400 with the policy's own error", async () => {
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
			result: { status: 400, error: "invalid_scope", errorDescription: "not today" },
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
			result: { status: 400, error: "invalid_request", errorDescription: "not today" },
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
			kindHook("evaluate-fallback", async () => ({ outcome: "deny", error: "slow_down" })),
			request,
			context,
			["read"],
			{ logger: { error: vi.fn(), warn: vi.fn() }, denyFallback: "invalid_grant" },
		);
		expect(outcome).toEqual({ ok: false, result: { status: 400, error: "invalid_grant" } });
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
			expect(outcome).toEqual({ ok: false, result: { status: 400, error: "invalid_request" } });
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
	// The rewrite line is written once per policy kind and code in a process,
	// so each test names its own kind.
	let kinds = 0;
	const fresh = () => ({ grantType: "test", policy: `policy-denied-${++kinds}` });
	const deny = (error: unknown, errorDescription?: unknown) =>
		readGrantPolicyDecision(
			{ outcome: "deny", error, ...(errorDescription !== undefined ? { errorDescription } : {}) },
			{ error: vi.fn() },
			fresh(),
		) as Extract<ReturnType<typeof readGrantPolicyDecision>, { verdict: "deny" }>;

	it.each([
		"invalid_request",
		"invalid_client",
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
		});
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it.each([
		["access_denied", "access_denied"],
		["the RFC 8628 polling code authorization_pending", "authorization_pending"],
		["the RFC 8628 polling code slow_down", "slow_down"],
		["the RFC 8628 polling code expired_token", "expired_token"],
		["another extension code", "consent_required"],
		["a code that differs only in case", "Invalid_Grant"],
	])("answers %s invalid_request by default, logging the policy's code", (_label, code) => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		expect(policyDenied(deny(code), logger, site)).toEqual({
			status: 400,
			error: "invalid_request",
		});
		expect(logger.warn.mock.calls).toEqual([
			[{ ...site, error: code, answered: "invalid_request" }, "grant_policy_refusal_rewritten"],
		]);
	});

	it("answers the caller's own fallback for a code outside the set", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		expect(policyDenied(deny("access_denied"), logger, site, "invalid_grant")).toEqual({
			status: 400,
			error: "invalid_grant",
		});
		expect(logger.warn).toHaveBeenCalledWith(
			{ ...site, error: "access_denied", answered: "invalid_grant" },
			"grant_policy_refusal_rewritten",
		);
	});

	it("logs a malformed code sanitised and capped, exactly as the audit stream records client text", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		policyDenied(deny(`bad"code\n\u0007${"x".repeat(300)}`), logger, site);
		expect(logger.warn.mock.calls).toEqual([
			[
				{ ...site, error: `bad?code??${"x".repeat(187)}...`, answered: "invalid_request" },
				"grant_policy_refusal_rewritten",
			],
		]);
	});

	it.each([
		["a number", 42, "(number)"],
		["no code", undefined, "(undefined)"],
		["the empty string", "", ""],
	])("answers %s as the code invalid_request, logging its type", (_label, code, logged) => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		expect(policyDenied(deny(code), logger, site)).toEqual({
			status: 400,
			error: "invalid_request",
		});
		expect(logger.warn).toHaveBeenCalledWith(
			{ ...site, error: logged, answered: "invalid_request" },
			"grant_policy_refusal_rewritten",
		);
	});

	it("logs a policy's rewritten code once per process, however often it denies with it", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		for (let i = 0; i < 5; i += 1) {
			expect(policyDenied(deny("access_denied"), logger, site)).toEqual({
				status: 400,
				error: "invalid_request",
			});
		}
		policyDenied(deny("slow_down"), logger, site);
		policyDenied(deny("access_denied"), logger, fresh());
		expect(logger.warn.mock.calls.map(([fields]) => [fields.policy, fields.error])).toEqual([
			[site.policy, "access_denied"],
			[site.policy, "slow_down"],
			[`policy-denied-${kinds}`, "access_denied"],
		]);
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
			expect(policyDenied(deny("invalid_scope", text), logger, fresh())).toEqual({
				status: 400,
				error: "invalid_scope",
				errorDescription: sent,
			});
			expect(logger.warn).not.toHaveBeenCalled();
		},
	);

	it.each([
		["the empty string", ""],
		["a number", 42],
	])("sends no description for %s, as one that is absent", (_label, text) => {
		expect(policyDenied(deny("invalid_scope", text), { warn: vi.fn() }, fresh())).toEqual({
			status: 400,
			error: "invalid_scope",
		});
	});

	it("keeps every character RFC 6749 §5.2 allows in a description", () => {
		const allowed = Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i))
			.filter((c) => c !== '"' && c !== "\\")
			.join("");
		expect(policyDenied(deny("invalid_scope", allowed), { warn: vi.fn() }, fresh())).toEqual({
			status: 400,
			error: "invalid_scope",
			errorDescription: allowed,
		});
	});

	it("names the caller's site on the line when it has one", () => {
		const logger = { warn: vi.fn() };
		const site = fresh();
		policyDenied(deny("access_denied"), logger, { ...site, site: "elsewhere" });
		expect(logger.warn).toHaveBeenCalledWith(
			{ site: "elsewhere", ...site, error: "access_denied", answered: "invalid_request" },
			"grant_policy_refusal_rewritten",
		);
	});
});
