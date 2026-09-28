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
import {
	checkStepUpPage,
	registeredRequirement,
	sealRegisteredReach,
} from "#/session-admission/requirement.mjs";
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
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
		...over,
	});

	it("answers each requirement by name and lists them in the order given", () => {
		const a = requirement("a");
		const b = requirement("b");
		const resolver = resolverForTests([b, a]);
		expect(resolver.get("a")?.name).toBe("a");
		expect(resolver.get("missing")).toBeUndefined();
		expect([...resolver.entries()].map(([name, r]) => [name, r.name])).toEqual([
			["b", "b"],
			["a", "a"],
		]);
	});

	it("holds remediations to the requirement's own routes — <name>.<route>, the route a lower-case identifier — each once, none a bundled action of another grade", () => {
		expect(
			resolverForTests([requirement("x", { remediations: ["x.step_up", "x.recover"] })]).get("x")
				?.remediations,
		).toEqual(["x.step_up", "x.recover"]);
		for (const remediations of [
			["oauth.authorize"],
			["x"],
			["x."],
			["x.Step"],
			["x.a.b"],
			["x.step-up"],
			["y.step_up"],
			[".step_up"],
			["x.step_up", "x.step_up"],
		]) {
			expect(
				() => resolverForTests([requirement("x", { remediations })]),
				JSON.stringify(remediations),
			).toThrow(RangeError);
		}
		// A bundled action of another grade is a consumer's, never a route a requirement owns.
		expect(() =>
			resolverForTests([requirement("oauth", { remediations: ["oauth.authorize"] })]),
		).toThrow(/oauth\.authorize/);
		expect(() => resolverForTests([requirement("mfa", { remediations: ["mfa.manage"] })])).toThrow(
			/mfa\.manage/,
		);
		// The bundled remediation is the MFA requirement's own route.
		expect(
			resolverForTests([requirement("mfa", { remediations: ["mfa.step_up"] })]).get("mfa")
				?.remediations,
		).toEqual(["mfa.step_up"]);
	});

	it("registers a copy, as boot does: the page and the lists are the copy's own, a page getter is read once, and admit delegates", async () => {
		let reads = 0;
		const asked: unknown[] = [];
		const source = {
			name: "x",
			reach: new Set(["risk-ok"]),
			get stepUpPage() {
				reads++;
				return { url: "/x", params: { n: String(reads) } };
			},
			remediations: ["x.step_up"],
			hintKeys: ["level"],
			admit: async (input: unknown) => {
				asked.push(input);
				return { outcome: "met" as const };
			},
		} satisfies SessionRequirement;
		const registered = resolverForTests([source]).get("x") as SessionRequirement;
		// Read once, at registration — before any matcher that might read it again.
		expect(reads).toBe(1);
		expect(registered === (source as unknown)).toBe(false);
		expect(Object.isFrozen(registered)).toBe(true);
		expect(registered.stepUpPage).toEqual({ url: "/x", params: { n: "1" } });
		(source.remediations as string[]).push("other");
		expect(registered.remediations).toEqual(["x.step_up"]);
		expect(registered.hintKeys).toEqual(["level"]);
		expect(registered.admitPrimary).toBeUndefined();
		await registered.admit({} as never);
		expect(asked).toHaveLength(1);
	});

	it("does not read reach at registration, so a reach that fills later — the MFA requirement's, over the factors — is read whole when it is sealed; resolverForTests seals as boot does, once, and a change after that is not seen", () => {
		let reads = 0;
		let reach = new Set<string>();
		const source = {
			name: "x",
			get reach() {
				reads++;
				return reach;
			},
			stepUpPage: { url: "/x", params: {} },
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" as const }),
		} satisfies SessionRequirement;
		expect(registeredRequirement(source).name).toBe("x");
		expect(reads).toBe(0);
		reach = new Set(["risk-ok"]);
		const registered = resolverForTests([source]).get("x") as SessionRequirement;
		expect(reads).toBe(1);
		expect([...registered.reach]).toEqual(["risk-ok"]);
		reach.add("other");
		reach = new Set(["swapped"]);
		expect([...registered.reach]).toEqual(["risk-ok"]);
		expect(reads).toBe(1);
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
			{ ...requirement("x"), remediations: "x" },
			{ ...requirement("x"), hintKeys: undefined },
			{ ...requirement("x"), hintKeys: [""] },
			{ ...requirement("x"), hintKeys: ["user"] },
			{ ...requirement("x"), hintKeys: ["Enrollable"] },
			{ ...requirement("x"), hintKeys: ["a-b"] },
			{ ...requirement("x"), admit: undefined },
			{ ...requirement("x"), admitPrimary: "later" },
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
		expect(resolverForTests([paged]).get("x")?.stepUpPage).toEqual(paged.stepUpPage);
	});
});

describe("sealRegisteredReach — a registered reach, read once after the name-keyed pass and sealed on the copy (D3)", () => {
	// `"none"` rather than `undefined`: a default parameter would replace an
	// explicit `undefined` with the page.
	const requirement = (
		name: string,
		reach: unknown,
		page: SessionRequirement["stepUpPage"] | "none" = { url: "/x", params: {} },
	): SessionRequirement =>
		({
			name,
			reach,
			stepUpPage: page === "none" ? undefined : page,
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
		}) as SessionRequirement;

	it("answers the reach as a set of its own, and lets the requirement named mfa reach the second-factor values", () => {
		const reach = new Set(["otp", "hwk", "mfa"]);
		const read = sealRegisteredReach(requirement("mfa", reach));
		expect([...read]).toEqual(["otp", "hwk", "mfa"]);
		expect(read).not.toBe(reach);
		expect([...sealRegisteredReach(requirement("risk", new Set(["risk-ok"])))]).toEqual([
			"risk-ok",
		]);
		expect(sealRegisteredReach(requirement("plain", new Set(), "none")).size).toBe(0);
	});

	it("reads the getter once", () => {
		let reads = 0;
		const source = requirement("x", undefined);
		Object.defineProperty(source, "reach", {
			get() {
				reads++;
				return new Set(["risk-ok"]);
			},
		});
		sealRegisteredReach(source);
		expect(reads).toBe(1);
	});

	it("seals a registered copy on a frozen snapshot: read once, answered afterwards without the source, unchanged by a contributor mutating or swapping its Set", () => {
		let reads = 0;
		const live = new Set(["risk-ok"]);
		let current = live;
		const source = {
			name: "risk",
			get reach() {
				reads++;
				return current;
			},
			stepUpPage: { url: "/risk", params: {} },
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" as const }),
		} satisfies SessionRequirement;
		const registered = registeredRequirement(source);
		const sealed = sealRegisteredReach(registered);
		expect(reads).toBe(1);
		expect([...sealed]).toEqual(["risk-ok"]);
		live.add("other");
		current = new Set(["swapped"]);
		expect(registered.reach).toBe(sealed);
		expect([...registered.reach]).toEqual(["risk-ok"]);
		expect(reads).toBe(1);
		expect(Object.isFrozen(sealed)).toBe(true);
		const mutable = sealed as Set<string>;
		expect(() => mutable.add("x")).toThrow(TypeError);
		expect(() => mutable.delete("risk-ok")).toThrow(TypeError);
		expect(() => mutable.clear()).toThrow(TypeError);
		expect([...sealed]).toEqual(["risk-ok"]);
	});

	it("answers a frozen set of its own for a requirement that is not a registered copy — the contract suite's fixture — and seals nothing on it", () => {
		const live = new Set(["risk-ok"]);
		const source = requirement("risk", live);
		const checked = sealRegisteredReach(source);
		expect(checked).not.toBe(live);
		live.add("other");
		expect([...checked]).toEqual(["risk-ok"]);
		expect(source.reach).toBe(live);
	});

	it("accepts an iterable of values that is not a string — an array — answering a Set, and seals a registered copy on it", () => {
		expect([...sealRegisteredReach(requirement("risk", ["risk-ok", "risk-ok"]))]).toEqual([
			"risk-ok",
		]);
		const registered = registeredRequirement(requirement("risk", ["risk-ok"]));
		sealRegisteredReach(registered);
		expect(registered.reach).toBeInstanceOf(Set);
		expect([...registered.reach]).toEqual(["risk-ok"]);
	});

	it.each([
		["a string", "risk-ok"],
		["a number", 7],
		["null", null],
		["undefined", undefined],
		["a list holding a reserved value", ["otp"]],
		["an empty string", new Set([""])],
		["a non-string", new Set([7])],
		["a primary's marker", new Set(["pwd"])],
		["the federated marker", new Set(["fed"])],
		["a second-factor value under another name", new Set(["otp"])],
		["mfa under another name", new Set(["mfa"])],
	])("refuses a reach that is %s with a RangeError", (_label, reach) => {
		expect(() => sealRegisteredReach(requirement("risk", reach))).toThrow(RangeError);
	});

	it("holds a page to a non-empty reach, and no page to an empty one", () => {
		expect(() => sealRegisteredReach(requirement("risk", new Set(["risk-ok"]), "none"))).toThrow(
			/where the step-up starts/,
		);
		expect(() => sealRegisteredReach(requirement("risk", new Set()))).toThrow(/reaches nothing/);
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
		expectTypeOf<RequirementInput["carrier"]>().toEqualTypeOf<
			"cookie" | "code" | "link" | "token"
		>();
		expectTypeOf<RequirementInput["now"]>().toEqualTypeOf<Date>();
		// A step_up names no page: admission answers the registered one.
		expectTypeOf<RequirementVerdict>().toEqualTypeOf<
			| { readonly outcome: "met" }
			| { readonly outcome: "reauthenticate" }
			| { readonly outcome: "step_up"; readonly whenStillUnmet: "reauthenticate" | "unmet" }
			| { readonly outcome: "unmet" }
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
