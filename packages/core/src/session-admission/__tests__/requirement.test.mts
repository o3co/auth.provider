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
	ADMISSION_ACTIONS,
	ADMISSION_INFRASTRUCTURE_STORES,
	checkStepUpPage,
	issuedRemediationActions,
	registeredRequirement,
	sealRegisteredReach,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { RecordedAuthentication } from "#/user-sessions/authentication.mjs";
import type { UserSessionClaims } from "#/user-sessions/types.mjs";

const ISSUER = "https://auth.test";

/** A resolver over a reaching non-mfa fixture: the reach rules boot holds lifted, the snapshot kept. */
const anyReach = (requirements: SessionRequirement[], issuer?: string) =>
	resolverForTests(requirements, {
		allowAnyReach: true,
		...(issuer === undefined ? {} : { issuer }),
	});

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

	it("refuses a path that leaves the issuer's origin once a browser resolves it — a backslash, an encoded backslash, a second slash — and a control character, with or without an issuer", () => {
		for (const url of [
			"/\\evil.test/step",
			"//evil.test/step",
			"/%5cevil.test",
			"/%5Cevil.test/step",
			"\\evil.test/step",
			"/step\u0000",
			"/st\nep",
			"/step\u007f",
			"/\tstep",
		]) {
			expect(() => checkStepUpPage({ url, params: {} }, ISSUER), JSON.stringify(url)).toThrow(
				RangeError,
			);
			expect(() => checkStepUpPage({ url, params: {} }), JSON.stringify(url)).toThrow(RangeError);
		}
		// A path resolves to the issuer's origin: kept as given.
		expect(checkStepUpPage({ url: "/step?next=1#top", params: {} }, ISSUER).url).toBe(
			"/step?next=1#top",
		);
	});

	it("copies params from their own enumerable keys, once: a Proxy that hides redirect_to from one probe, or a getter that changes type between reads, cannot get past", () => {
		let probes = 0;
		const hiding = new Proxy(
			{},
			{
				getOwnPropertyDescriptor(_target, key) {
					if (key !== "redirect_to") return undefined;
					probes++;
					return probes <= 1
						? undefined
						: { value: "https://evil.test", enumerable: true, configurable: true, writable: true };
				},
				ownKeys: () => ["redirect_to"],
				get: (_target, key) => (key === "redirect_to" ? "https://evil.test" : undefined),
			},
		);
		expect(() => checkStepUpPage({ url: "/mfa", params: hiding }, ISSUER)).toThrow(/redirect_to/);
		let reads = 0;
		const shifting = {
			get a() {
				reads++;
				return reads === 1 ? "ok" : { toString: () => "x" };
			},
		};
		const page = checkStepUpPage({ url: "/mfa", params: shifting }, ISSUER);
		expect(page.params).toEqual({ a: "ok" });
		expect(typeof page.params.a).toBe("string");
		// The consumer's return parameter in the page's own query is refused too.
		expect(() =>
			checkStepUpPage({ url: "/mfa?redirect_to=https://evil.test", params: {} }, ISSUER),
		).toThrow(/redirect_to/);
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

	it("holds remediations to the requirement's own routes — <name>.<route>, the route a lower-case identifier — each once, and never a consumer's action, which may share the namespace", () => {
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
		// A consumer's action may share a requirement's namespace (`mfa.manage`,
		// or a requirement named `oauth`): any name in `ADMISSION_ACTIONS` is
		// refused, since a remediation under it would skip every requirement
		// for that action.
		expect(Object.hasOwn(ADMISSION_ACTIONS, "mfa.step_up")).toBe(false);
		expect(() =>
			resolverForTests([requirement("oauth", { remediations: ["oauth.authorize"] })]),
		).toThrow(/oauth\.authorize/);
		expect(() => resolverForTests([requirement("mfa", { remediations: ["mfa.manage"] })])).toThrow(
			/mfa\.manage/,
		);
		expect(
			resolverForTests([requirement("mfa", { remediations: ["mfa.step_up"] })]).get("mfa")
				?.remediations,
		).toEqual(["mfa.step_up"]);
	});

	it("issues one branded remediation action per declared route to the module that holds the requirement object — issuedRemediationActions(original) — never through the resolver", () => {
		const original = requirement("x", { remediations: ["x.step_up", "x.recover"] });
		expect(issuedRemediationActions(original)).toBeUndefined();
		const registered = resolverForTests([original]).get("x");
		const issued = issuedRemediationActions(original);
		expect(issued).toEqual({
			step_up: { name: "x.step_up", grade: "remediation" },
			recover: { name: "x.recover", grade: "remediation" },
		});
		expect(Object.isFrozen(issued)).toBe(true);
		expect(Object.isFrozen(issued?.step_up)).toBe(true);
		// The resolver hands out the registered copy, which carries none of
		// them: a consumer with the resolver cannot mint a remediation action.
		expect("actions" in (registered as object)).toBe(false);
		expect(issuedRemediationActions(registered as SessionRequirement)).toBeUndefined();
		expect(issuedRemediationActions({ ...original })).toBeUndefined();
		const bare = requirement("y");
		registeredRequirement(bare);
		expect(issuedRemediationActions(bare)).toEqual({});
	});

	it("reads each field of the value once, into a copy it validates: a getter answering differently to a second read changes nothing", () => {
		let names = 0;
		const renaming = {
			...requirement("x", { remediations: ["oauth.authorize"] }),
			get name() {
				names++;
				return names === 1 ? "oauth" : "x";
			},
		};
		// Read once as "oauth": its remediation is a consumer's action, refused.
		expect(() => resolverForTests([renaming as never])).toThrow(/oauth\.authorize/);
		let reads = 0;
		const swapping = {
			...requirement("x"),
			get remediations() {
				reads++;
				return reads === 1 ? ["x.ok"] : ["mfa.step_up", "oauth.authorize"];
			},
		};
		const registered = resolverForTests([swapping as never]).get("x");
		expect(registered?.remediations).toEqual(["x.ok"]);
		expect(Object.keys(issuedRemediationActions(swapping as never) ?? {})).toEqual(["ok"]);
		let keys = 0;
		const hinting = {
			...requirement("x"),
			get hintKeys() {
				keys++;
				return keys === 1 ? ["level"] : ["user"];
			},
		};
		expect(resolverForTests([hinting as never]).get("x")?.hintKeys).toEqual(["level"]);
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
		const registered = anyReach([source]).get("x") as SessionRequirement;
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
		const registered = anyReach([source]).get("x") as SessionRequirement;
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

	it("refuses a name admission gives an outage of one of its own stores — ADMISSION_INFRASTRUCTURE_STORES, user_session and revocation_boundary — which a consumer telling an outage by its store would take the requirement's for", () => {
		expect(ADMISSION_INFRASTRUCTURE_STORES).toEqual(["user_session", "revocation_boundary"]);
		expect(Object.isFrozen(ADMISSION_INFRASTRUCTURE_STORES)).toBe(true);
		for (const name of ADMISSION_INFRASTRUCTURE_STORES) {
			expect(() => resolverForTests([requirement(name)]), name).toThrow(RangeError);
			expect(() => resolverForTests([requirement(name)]), name).toThrow(/outage/);
		}
		// A name that only shares a prefix is another name.
		expect(
			resolverForTests([requirement("user_session_age")]).get("user_session_age"),
		).toBeDefined();
	});

	it("holds a name to RFC 6749's error-code characters, the ones a step_up is sent in — printable ASCII without a quote or a backslash — and accepts any of them", () => {
		for (const name of [
			'a "quoted" name',
			"back\\slash",
			"tab\there",
			"new\nline",
			"del\u007f",
			"caf\u00e9",
			"\u{1F512}",
		]) {
			expect(() => resolverForTests([requirement(name)]), JSON.stringify(name)).toThrow(
				/error-code characters/,
			);
		}
		for (const name of ["deployment:requirement-page", "a b", "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"]) {
			expect(resolverForTests([requirement(name)]).get(name)?.name, name).toBe(name);
		}
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

	it("holds a fixture to boot's rules by default — a non-empty reach under any name but mfa, a reserved value, a reach without a page are refused — and lifts the reach rules under allowAnyReach for the merge-table tests", () => {
		const page = { url: "/x", params: {} };
		expect(() =>
			resolverForTests([requirement("x", { reach: new Set(["risk-ok"]), stepUpPage: page })]),
		).toThrow(/mfa/);
		expect(() =>
			resolverForTests([requirement("x", { reach: new Set(["otp"]), stepUpPage: page })]),
		).toThrow(RangeError);
		expect(() => resolverForTests([requirement("x", { reach: new Set(["risk-ok"]) })])).toThrow(
			/where the step-up starts/,
		);
		expect(
			resolverForTests([
				requirement("mfa", {
					reach: new Set(["otp", "mfa"]),
					stepUpPage: page,
					remediations: ["mfa.step_up"],
				}),
			])
				.get("mfa")
				?.reach.has("otp"),
		).toBe(true);
		const lifted = resolverForTests(
			[requirement("x", { reach: new Set(["risk-ok"]), stepUpPage: page })],
			{ allowAnyReach: true },
		);
		expect([...(lifted.get("x")?.reach ?? [])]).toEqual(["risk-ok"]);
		// Still sealed under the opt-out: a snapshot, not the contributor's Set.
		const sealed = lifted.get("x")?.reach as object;
		expect("add" in sealed).toBe(false);
	});

	it("holds the page to the issuer given, and to its shape alone when none is", () => {
		const paged = requirement("x", {
			reach: new Set(["otp"]),
			stepUpPage: { url: "https://other.test/x", params: {} },
		});
		expect(() => anyReach([paged], ISSUER)).toThrow(RangeError);
		expect(anyReach([paged]).get("x")?.stepUpPage).toEqual(paged.stepUpPage);
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
		// A read-only view over a private set — not a native Set, which a
		// frozen one still lets add and delete: has, size and iteration alone.
		expect(sealed instanceof Set).toBe(false);
		for (const method of ["add", "delete", "clear"]) {
			expect(method in sealed, method).toBe(false);
		}
		const mutable = sealed as Set<string>;
		expect(() => mutable.add("x")).toThrow(TypeError);
		expect(() => mutable.delete("risk-ok")).toThrow(TypeError);
		expect(() => mutable.clear()).toThrow(TypeError);
		expect(sealed.has("risk-ok")).toBe(true);
		expect(sealed.has("other")).toBe(false);
		expect(sealed.size).toBe(1);
		expect([...sealed]).toEqual(["risk-ok"]);
		expect([...sealed.keys()]).toEqual(["risk-ok"]);
		expect([...sealed.values()]).toEqual(["risk-ok"]);
		expect([...sealed.entries()]).toEqual([["risk-ok", "risk-ok"]]);
		const seen: string[] = [];
		sealed.forEach((value) => {
			seen.push(value);
		});
		expect(seen).toEqual(["risk-ok"]);
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
		expect("add" in registered.reach).toBe(false);
		expect(registered.reach.has("risk-ok")).toBe(true);
		expect(registered.reach.size).toBe(1);
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

	it("requires a page of a non-empty reach, and lets a requirement that reaches nothing register one: a step-up that adds no value — a re-consent — still has somewhere to start", () => {
		expect(() => sealRegisteredReach(requirement("risk", new Set(["risk-ok"]), "none"))).toThrow(
			/where the step-up starts/,
		);
		expect(sealRegisteredReach(requirement("risk", new Set())).size).toBe(0);
		expect(sealRegisteredReach(requirement("plain", new Set(), "none")).size).toBe(0);
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
			readonly claims: UserSessionClaims;
			readonly recorded: RecordedAuthentication;
			readonly authTime: Date;
			readonly redirectTo: string | undefined;
			readonly request: { readonly ip?: string; readonly userAgent?: string };
		}>();
		expect(true).toBe(true);
	});
});

describe("the refusals and the read-only view, each driven", () => {
	const mfa = {
		name: "mfa",
		reach: new Set(["otp", "mfa"]),
		stepUpPage: { url: "/mfa", params: {} },
		remediations: ["mfa.step_up"],
		hintKeys: [],
		admit: async () => ({ outcome: "met" as const }),
	} satisfies SessionRequirement;

	it("a sealed reach answers the set algebra over a copy of its own — never the private set — and names itself", () => {
		const reach = resolverForTests([mfa]).get("mfa")?.reach as ReadonlySet<string>;
		expect(Object.prototype.toString.call(reach)).toBe("[object SealedReach]");
		const other = new Set(["hwk", "otp"]);
		const union = reach.union(other);
		expect([...union].sort()).toEqual(["hwk", "mfa", "otp"]);
		union.add("x");
		expect(reach.has("x")).toBe(false);
		expect([...reach.intersection(other)]).toEqual(["otp"]);
		expect([...reach.difference(other)]).toEqual(["mfa"]);
		expect([...reach.symmetricDifference(other)].sort()).toEqual(["hwk", "mfa"]);
		expect(reach.isSubsetOf(new Set(["otp", "mfa", "hwk"]))).toBe(true);
		expect(reach.isSubsetOf(other)).toBe(false);
		expect(reach.isSupersetOf(new Set(["otp"]))).toBe(true);
		expect(reach.isSupersetOf(other)).toBe(false);
		expect(reach.isDisjointFrom(new Set(["hwk"]))).toBe(true);
		expect(reach.isDisjointFrom(other)).toBe(false);
	});

	it("allowAnyReach still refuses a reach that is not a Set or another iterable", () => {
		for (const reach of [7, "otp", null, undefined, { otp: true }]) {
			expect(
				() =>
					resolverForTests([{ ...mfa, name: "x", remediations: [], reach } as never], {
						allowAnyReach: true,
					}),
				JSON.stringify(reach),
			).toThrow(/reach must be a Set of amr values/);
		}
	});

	it("issuedRemediationActions answers nothing for what is not an object", () => {
		for (const value of [undefined, null, "mfa", 7]) {
			expect(issuedRemediationActions(value as never), String(value)).toBeUndefined();
		}
	});
});
