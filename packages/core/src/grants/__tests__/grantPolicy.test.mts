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

import { describe, expect, it } from "vitest";
import {
	boundPolicyAudience,
	evaluateGrantPolicy,
	policyOutOfBounds,
} from "#/grants/grantPolicy.mjs";
import type {
	GrantPolicyContext,
	GrantPolicyDecision,
	GrantPolicyHook,
	GrantPolicyRequest,
} from "#/policy/types.mjs";

/**
 * #520 — the one answer every minting path gives a policy that throws,
 * denies, or exceeds its ceiling. Grants used to carry their own copies of
 * these rules, and the copies disagreed (WebAuthn let a policy originate an
 * audience with no client; four grants called a policy fault a client error).
 */

const hook = (decide: () => Promise<GrantPolicyDecision>): GrantPolicyHook => ({
	kind: "stub",
	evaluate: decide,
});
const allow = (extra: Partial<Extract<GrantPolicyDecision, { outcome: "allow" }>> = {}) =>
	hook(async () => ({ outcome: "allow", ...extra }));

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

describe("evaluateGrantPolicy", () => {
	it("answers 503 temporarily_unavailable when the policy throws — fail closed, never open", async () => {
		const outcome = await evaluateGrantPolicy(
			hook(async () => {
				throw new Error("policy service down");
			}),
			request,
			context,
			["read"],
		);
		expect(outcome).toEqual({
			ok: false,
			result: {
				status: 503,
				error: "temporarily_unavailable",
				errorDescription: "policy evaluation unavailable",
			},
		});
	});

	it("passes a deny through as 400 with the policy's own error", async () => {
		const outcome = await evaluateGrantPolicy(
			hook(async () => ({
				outcome: "deny",
				error: "access_denied",
				errorDescription: "not today",
			})),
			request,
			context,
			["read"],
		);
		expect(outcome).toEqual({
			ok: false,
			result: { status: 400, error: "access_denied", errorDescription: "not today" },
		});
	});

	it("leaves the effective scope alone when the policy says nothing about it", async () => {
		const outcome = await evaluateGrantPolicy(allow(), request, context, ["read", "write"]);
		expect(outcome).toMatchObject({ ok: true, scopes: ["read", "write"] });
	});

	it("narrows to what the policy grants, and honours an empty array as strip-all", async () => {
		expect(
			await evaluateGrantPolicy(allow({ grantedScope: ["read"] }), request, context, [
				"read",
				"write",
			]),
		).toMatchObject({ ok: true, scopes: ["read"] });
		expect(
			await evaluateGrantPolicy(allow({ grantedScope: [] }), request, context, ["read"]),
		).toMatchObject({ ok: true, scopes: [] });
	});

	it("refuses a policy that widens past the effective scope as 500 server_error naming the extra", async () => {
		const outcome = await evaluateGrantPolicy(
			allow({ grantedScope: ["read", "admin"] }),
			request,
			context,
			["read"],
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

	it("hands the allow decision back so the caller can bound its audience", async () => {
		const outcome = await evaluateGrantPolicy(
			allow({ grantedAudience: ["https://api.example"] }),
			request,
			context,
			["read"],
		);
		expect(outcome.ok && outcome.decision.grantedAudience).toEqual(["https://api.example"]);
	});

	it("refuses a non-array grantedScope as 500 server_error instead of throwing (#521)", async () => {
		// A JS policy returning a string passes a truthiness check, and
		// `.filter` then throws a TypeError that /token dispatch does not
		// catch — fail-closed, but ungraceful.
		const outcome = await evaluateGrantPolicy(
			allow({ grantedScope: "read" as unknown as readonly string[] }),
			request,
			context,
			["read"],
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

	it("refuses a non-array grantedAudience as 500 server_error instead of throwing (#521)", () => {
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
