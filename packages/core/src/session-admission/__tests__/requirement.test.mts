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
 * The requirement vocabulary (the session-admission ADR's D2, D3): the
 * step-up page as it is validated, the resolver `resolverForTests` builds
 * for a test, and the shapes the contract names.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type {
	PrimaryAuthentication,
	RequirementInput,
	RequirementSession,
	RequirementVerdict,
	SessionRequirement,
	SessionView,
} from "#/session-admission/requirement.mjs";
import { checkStepUpPage } from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { RecordedAuthentication } from "#/user-sessions/authentication.mjs";

const ISSUER = "https://auth.test";

describe("checkStepUpPage — the deployment's page for a step-up (D2, D3)", () => {
	it("accepts a path, and an absolute URL on the issuer's origin, answering a frozen copy", () => {
		for (const url of ["/mfa", "/account/mfa?step=1", `${ISSUER}/mfa`, `${ISSUER}/a/b#c`]) {
			const page = checkStepUpPage({ url, params: { hint: "x" } }, ISSUER);
			expect(page, url).toEqual({ url, params: { hint: "x" } });
			expect(Object.isFrozen(page), url).toBe(true);
			expect(Object.isFrozen(page.params), url).toBe(true);
		}
		const params = { a: "1" };
		const page = checkStepUpPage({ url: "/mfa", params }, ISSUER);
		params.a = "2";
		expect(page.params.a).toBe("1");
	});

	it("refuses a URL on another origin, a scheme-relative or relative one, and one that is not a string", () => {
		for (const url of [
			"https://evil.test/mfa",
			"http://auth.test/mfa",
			"https://auth.test:8443/mfa",
			"//evil.test/mfa",
			"mfa",
			"",
			"javascript:alert(1)",
			7,
			undefined,
		]) {
			expect(() => checkStepUpPage({ url, params: {} }, ISSUER), String(url)).toThrow(RangeError);
		}
	});

	it("refuses params that carry redirect_to — the consumer's return parameter — or a value that is not a string", () => {
		expect(() => checkStepUpPage({ url: "/mfa", params: { redirect_to: "/x" } }, ISSUER)).toThrow(
			/redirect_to/,
		);
		for (const params of [{ n: 1 }, { n: null }, { n: ["a"] }, "a=b", null, undefined]) {
			expect(
				() => checkStepUpPage({ url: "/mfa", params: params as never }, ISSUER),
				JSON.stringify(params),
			).toThrow(RangeError);
		}
	});

	it("refuses what is not a page", () => {
		for (const page of [undefined, null, "/mfa", { params: {} }]) {
			expect(() => checkStepUpPage(page, ISSUER), String(page)).toThrow(RangeError);
		}
	});

	it("validates the shape alone when no issuer is given: any absolute URL passes, a relative one does not", () => {
		expect(checkStepUpPage({ url: "https://other.test/mfa", params: {} }).url).toBe(
			"https://other.test/mfa",
		);
		expect(() => checkStepUpPage({ url: "mfa", params: {} })).toThrow(RangeError);
	});
});

describe("resolverForTests — the resolver a test builds (D1)", () => {
	const requirement = (
		name: string,
		over: Partial<SessionRequirement> = {},
	): SessionRequirement => ({
		name,
		reach: new Set(),
		stepUpPage: undefined,
		remediations: [],
		admit: async () => ({ outcome: "met" }),
		...over,
	});

	it("answers each requirement by name and lists them in the order given", () => {
		const a = requirement("a");
		const b = requirement("b");
		const resolver = resolverForTests([b, a]);
		expect(resolver.get("a")).toBe(a);
		expect(resolver.get("missing")).toBeUndefined();
		expect([...resolver.entries()]).toEqual([
			["b", b],
			["a", a],
		]);
	});

	it("exposes get and entries alone, frozen", () => {
		const resolver = resolverForTests([]);
		expect(Object.keys(resolver).sort()).toEqual(["entries", "get"]);
		expect(Object.isFrozen(resolver)).toBe(true);
	});

	it("refuses two requirements of one name, and a requirement that is not one", () => {
		expect(() => resolverForTests([requirement("a"), requirement("a")])).toThrow(RangeError);
		for (const bad of [
			undefined,
			null,
			{ name: "" },
			{ ...requirement("x"), reach: ["otp"] },
			{ ...requirement("x"), remediations: "x" },
			{ ...requirement("x"), admit: undefined },
			{ ...requirement("x"), reach: new Set(["otp"]) },
			{ ...requirement("x"), stepUpPage: { url: "/x", params: {} } },
			{ ...requirement("x"), stepUpPage: { url: "mfa", params: {} }, reach: new Set(["otp"]) },
		]) {
			expect(() => resolverForTests([bad as never]), JSON.stringify(bad)).toThrow(RangeError);
		}
		expect(() => resolverForTests("x" as never)).toThrow(RangeError);
	});

	it("holds the page to the issuer given, and to its shape alone when none is", () => {
		const paged = requirement("x", {
			reach: new Set(["otp"]),
			stepUpPage: { url: "https://other.test/x", params: {} },
		});
		expect(() => resolverForTests([paged], { issuer: ISSUER })).toThrow(RangeError);
		expect(resolverForTests([paged]).get("x")).toBe(paged);
	});
});

describe("the shapes the contract names", () => {
	it("RequirementInput is a view, the D9 reading, the action, the asks and now", () => {
		expectTypeOf<RequirementInput["session"]>().toEqualTypeOf<SessionView | null>();
		expectTypeOf<SessionView>().toEqualTypeOf<{
			readonly sid: string;
			readonly sub: string;
			readonly authTime: Date;
			readonly expiresAt: Date;
		}>();
		expectTypeOf<RequirementInput["authentication"]>().toEqualTypeOf<RequirementSession | null>();
		expectTypeOf<RequirementInput["now"]>().toEqualTypeOf<Date>();
		expectTypeOf<RequirementVerdict["outcome"]>().toEqualTypeOf<
			"met" | "reauthenticate" | "step_up" | "unmet"
		>();
		expect(true).toBe(true);
	});

	it("PrimaryAuthentication carries what a login path records, never a method and amr of its own", () => {
		expectTypeOf<PrimaryAuthentication>().toEqualTypeOf<{
			readonly subject: string;
			readonly user: Readonly<Record<string, unknown>>;
			readonly recorded: RecordedAuthentication;
			readonly authTime: Date;
			readonly redirectTo: string | undefined;
			readonly request: { readonly ip?: string; readonly userAgent?: string };
		}>();
		expect(true).toBe(true);
	});
});
