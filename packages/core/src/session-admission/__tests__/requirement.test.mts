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
import type { MfaEnrollmentWitness } from "#/repositories/UserRepository.mjs";
import type { AdmissionAction } from "#/session-admission/actions.mjs";
import type {
	AdmissionRequest,
	IssuedRemediationAction,
	PrimaryAuthentication,
	RegisteredRequirement,
	RequirementInput,
	RequirementSession,
	RequirementVerdict,
	SessionRequirement,
	SessionView,
} from "#/session-admission/requirement.mjs";
import {
	ADMISSION_INFRASTRUCTURE_STORES,
	checkStepUpPage,
	describeAdmissionOutage,
	issuedRemediationActions,
	registeredRequirement,
	sealRegisteredReach,
	secondFactorAuthorities,
	stepUpPageUrl,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { RecordedAuthentication } from "#/user-sessions/authentication.mjs";
import type { SessionEnrollmentFacts, UserSessionClaims } from "#/user-sessions/types.mjs";

const ISSUER = "https://auth.test";

/** A resolver over a reaching non-mfa fixture: the reach rules boot holds lifted, the snapshot kept. */
const anyReach = (requirements: SessionRequirement[], issuer?: string) =>
	resolverForTests(requirements, {
		allowAnyReach: true,
		...(issuer === undefined ? {} : { issuer }),
	});

describe("checkStepUpPage — the deployment's page for a step-up", () => {
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

describe("stepUpPageUrl — the step-up page as a browser is sent to it", () => {
	it("resolves a path on the issuer and sets each param on the query: one absolute URL string", () => {
		expect(
			stepUpPageUrl(
				checkStepUpPage({ url: "/mfa/step-up", params: { flow: "device", ui: "compact" } }),
				ISSUER,
			),
		).toBe(`${ISSUER}/mfa/step-up?flow=device&ui=compact`);
	});

	it("keeps an absolute page's own query and sets the params beside it, a param of the same name replacing it", () => {
		expect(
			stepUpPageUrl(
				checkStepUpPage({ url: `${ISSUER}/mfa?x=1&keep=a`, params: { flow: "link", x: "2" } }),
				ISSUER,
			),
		).toBe(`${ISSUER}/mfa?x=2&keep=a&flow=link`);
	});

	it("resolves a path against the issuer's origin, as a browser resolves a Location — an issuer with a path included", () => {
		expect(stepUpPageUrl({ url: "/mfa", params: {} }, "https://auth.test/tenant/a")).toBe(
			"https://auth.test/mfa",
		);
	});

	it("encodes each param as a query value, never concatenated", () => {
		const url = stepUpPageUrl({ url: "/mfa", params: { note: "a b&c=d#e", "k y": "é" } }, ISSUER);
		expect(url).toBe(`${ISSUER}/mfa?note=a+b%26c%3Dd%23e&k+y=%C3%A9`);
		const read = new URL(url);
		expect(read.searchParams.get("note")).toBe("a b&c=d#e");
		expect(read.searchParams.get("k y")).toBe("é");
		expect(read.hash).toBe("");
	});

	it("adds no return parameter: redirect_to is the consumer's, set on its own trip", () => {
		const url = new URL(stepUpPageUrl({ url: "/mfa", params: { flow: "x" } }, ISSUER));
		expect(url.searchParams.has("redirect_to")).toBe(false);
		expect([...url.searchParams.keys()]).toEqual(["flow"]);
	});
});

describe("the registered page — resolved once, at registration, on the issuer it was validated on", () => {
	const paged = (stepUpPage: SessionRequirement["stepUpPage"]): SessionRequirement => ({
		name: "x",
		reach: new Set(),
		stepUpPage,
		remediations: [],
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
	});

	it("carries href: the page's url resolved on the issuer, its params on the query — one absolute URL with no return parameter, frozen with the copy", () => {
		const page = { url: "/mfa/step-up", params: { flow: "x" } };
		const registered = registeredRequirement(paged(page), ISSUER);
		expect(registered.stepUpPage).toEqual({ ...page, href: `${ISSUER}/mfa/step-up?flow=x` });
		expect(registered.stepUpPage?.href).toBe(stepUpPageUrl(page, ISSUER));
		expect(Object.isFrozen(registered.stepUpPage)).toBe(true);
		expect(new URL(registered.stepUpPage?.href ?? "").searchParams.has("redirect_to")).toBe(false);
	});

	it("resolves an absolute page on the issuer's origin as it is — and, with no issuer, on itself", () => {
		expect(
			registeredRequirement(paged({ url: `${ISSUER}/mfa?x=1`, params: { flow: "y" } }), ISSUER)
				.stepUpPage?.href,
		).toBe(`${ISSUER}/mfa?x=1&flow=y`);
		expect(
			registeredRequirement(paged({ url: "https://other.test/mfa", params: {} })).stepUpPage?.href,
		).toBe("https://other.test/mfa");
	});

	it("refuses a path page with no issuer to resolve it on, saying where the issuer comes from", () => {
		const path = paged({ url: "/mfa", params: {} });
		expect(() => registeredRequirement(path)).toThrow(RangeError);
		expect(() => registeredRequirement(path)).toThrow(
			/stepUpPage\.url "\/mfa" is a path, resolved on the issuer: none was given/,
		);
		expect(() => resolverForTests([path])).toThrow(
			/resolverForTests\(requirements, \{ issuer \}\)/,
		);
		expect(resolverForTests([path], { issuer: ISSUER }).get("x")?.stepUpPage?.href).toBe(
			`${ISSUER}/mfa`,
		);
	});

	it("registers no page for a requirement that declares none", () => {
		expect(registeredRequirement(paged(undefined)).stepUpPage).toBeUndefined();
		expect(registeredRequirement(paged(undefined), ISSUER).stepUpPage).toBeUndefined();
	});
});

describe("resolverForTests — the resolver a test builds", () => {
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

	it("holds remediations to the requirement's own routes — <name>.<route>, the route a lower-case identifier — each once, and never a registered action's name, which may share the namespace", () => {
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
		// A consumer's action may share a requirement's namespace: a registered
		// action's name is refused, since a remediation under it would skip every
		// requirement for that action.
		expect(() =>
			resolverForTests([requirement("oauth", { remediations: ["oauth.authorize"] })], {
				actions: { "oauth.authorize": { grade: "use" } },
			}),
		).toThrow(/oauth\.authorize/);
		expect(
			resolverForTests([requirement("mfa", { remediations: ["mfa.step_up"] })], {
				actions: { "mfa.manage": { grade: "credential_change" } },
			}).get("mfa")?.remediations,
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
		// Read once as "oauth": its remediation is its own route, so it registers.
		expect(resolverForTests([renaming as never]).get("oauth")?.remediations).toEqual([
			"oauth.authorize",
		]);
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
		const registered = anyReach([source], ISSUER).get("x") as SessionRequirement;
		// Read once, at registration — before any matcher that might read it again.
		expect(reads).toBe(1);
		expect(registered === (source as unknown)).toBe(false);
		expect(Object.isFrozen(registered)).toBe(true);
		expect(registered.stepUpPage).toEqual({
			url: "/x",
			params: { n: "1" },
			href: `${ISSUER}/x?n=1`,
		});
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
		expect(registeredRequirement(source, ISSUER).name).toBe("x");
		expect(reads).toBe(0);
		reach = new Set(["risk-ok"]);
		const registered = anyReach([source], ISSUER).get("x") as SessionRequirement;
		expect(reads).toBe(1);
		expect([...registered.reach]).toEqual(["risk-ok"]);
		reach.add("other");
		reach = new Set(["swapped"]);
		expect([...registered.reach]).toEqual(["risk-ok"]);
		expect(reads).toBe(1);
	});

	it("exposes get, entries and action alone, frozen", () => {
		const resolver = resolverForTests([]);
		expect(Object.keys(resolver).sort()).toEqual(["action", "entries", "get"]);
		expect(Object.isFrozen(resolver)).toBe(true);
	});

	it("registers whether a requirement declares the second-factor authority — true when it says so, false when it says false or nothing — read once, and refuses a declaration that is neither", () => {
		expect(
			resolverForTests([requirement("second", { secondFactorAuthority: true })]).get("second")
				?.secondFactorAuthority,
		).toBe(true);
		expect(
			resolverForTests([requirement("x", { secondFactorAuthority: false })]).get("x")
				?.secondFactorAuthority,
		).toBe(false);
		expect(resolverForTests([requirement("x")]).get("x")?.secondFactorAuthority).toBe(false);
		// The name is not a declaration: `mfa` saying nothing is not the authority.
		expect(resolverForTests([requirement("mfa")]).get("mfa")?.secondFactorAuthority).toBe(false);
		for (const declared of ["yes", 1, null, {}]) {
			expect(
				() => resolverForTests([requirement("x", { secondFactorAuthority: declared as never })]),
				JSON.stringify(declared),
			).toThrow(/secondFactorAuthority must be true, false or absent/);
		}
		let reads = 0;
		const flipping = {
			...requirement("x"),
			get secondFactorAuthority() {
				reads++;
				return reads === 1;
			},
		};
		const registered = resolverForTests([flipping as never]).get("x");
		expect(registered?.secondFactorAuthority).toBe(true);
		expect(registered?.secondFactorAuthority).toBe(true);
		expect(reads).toBe(1);
	});

	it("refuses a second requirement that declares the second-factor authority, naming both: at most one registered requirement may", () => {
		const declaring = (name: string) => requirement(name, { secondFactorAuthority: true });
		expect(() => resolverForTests([declaring("first"), declaring("second")])).toThrow(
			/"first" and "second" both declare the second-factor authority/,
		);
		// One authority beside any number that do not declare it.
		const resolver = resolverForTests([requirement("a"), declaring("first"), requirement("b")]);
		expect(
			[...resolver.entries()].filter(([, r]) => r.secondFactorAuthority).map(([name]) => name),
		).toEqual(["first"]);
		// Lifting the reach rules does not lift this one.
		expect(() =>
			resolverForTests([declaring("first"), declaring("second")], { allowAnyReach: true }),
		).toThrow(/both declare the second-factor authority/);
	});

	it("secondFactorAuthorities answers the registered requirements that declare the authority, in the order given: the one home of the at-most-one rule", () => {
		const resolver = anyReach([
			requirement("a"),
			requirement("first", { secondFactorAuthority: true }),
			requirement("b", { secondFactorAuthority: false }),
		]);
		const registered = [...resolver.entries()].map(([, r]) => r);
		expect(secondFactorAuthorities(registered).map((r) => r.name)).toEqual(["first"]);
		expect(secondFactorAuthorities([])).toEqual([]);
	});

	it("refuses a second authority before it seals any reach, as boot does: the duplicate is named even when the first one's reach is refused too", () => {
		const badReach = requirement("first", {
			secondFactorAuthority: true,
			reach: new Set(["pwd"]),
			stepUpPage: { url: "https://auth.test/first", params: {} },
		});
		const second = requirement("second", { secondFactorAuthority: true });
		expect(() => resolverForTests([badReach, second])).toThrow(
			/"first" and "second" both declare the second-factor authority/,
		);
		// Alone, the first is refused for its reach.
		expect(() => resolverForTests([badReach])).toThrow(/a primary's marker/);
	});

	it("refuses a name admission gives an outage of one of its own stores — ADMISSION_INFRASTRUCTURE_STORES, user_session and revocation_boundary — which a consumer telling an outage by its store would take the requirement's for", () => {
		expect(ADMISSION_INFRASTRUCTURE_STORES).toEqual(["user_session", "revocation_boundary"]);
		expect(Object.isFrozen(ADMISSION_INFRASTRUCTURE_STORES)).toBe(true);
		for (const name of ADMISSION_INFRASTRUCTURE_STORES) {
			expect(() => resolverForTests([requirement(name)]), name).toThrow(RangeError);
			// Worded by the two names, not by a constant core does not export.
			expect(() => resolverForTests([requirement(name)]), name).toThrow(
				/the name is one admission gives an outage of its own stores \(user_session, revocation_boundary\)/,
			);
			expect(() => resolverForTests([requirement(name)]), name).not.toThrow(
				/ADMISSION_INFRASTRUCTURE_STORES/,
			);
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

	it("describes an outage by the store an unavailable admission names — each of admission's own by name, anything else as a requirement's", () => {
		expect(describeAdmissionOutage("user_session")).toBe("session store unavailable");
		expect(describeAdmissionOutage("revocation_boundary")).toBe("revocation store unavailable");
		for (const name of ADMISSION_INFRASTRUCTURE_STORES) {
			expect(describeAdmissionOutage(name), name).not.toBe("session requirement unavailable");
		}
		for (const name of ["fixture", "mfa", "deployment:requirement-page"]) {
			expect(describeAdmissionOutage(name), name).toBe("session requirement unavailable");
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

	it("holds a fixture to boot's rules by default — a non-empty reach from a requirement that does not declare the second-factor authority, a reserved value, a reach without a page are refused — and lifts the reach rules under allowAnyReach for the merge-table tests", () => {
		const page = { url: "/x", params: {} };
		const onIssuer = { issuer: ISSUER };
		// The seal's refusal, with the remedy a test has: the opt-out below.
		expect(() =>
			resolverForTests(
				[requirement("x", { reach: new Set(["risk-ok"]), stepUpPage: page })],
				onIssuer,
			),
		).toThrow(
			/only the second-factor authority adds vouched values to a session, so any other reach must be empty — pass allowAnyReach for a test of admission's own mechanics$/,
		);
		expect(() =>
			resolverForTests([requirement("x", { reach: new Set(["otp"]), stepUpPage: page })], onIssuer),
		).toThrow(RangeError);
		expect(() => resolverForTests([requirement("x", { reach: new Set(["risk-ok"]) })])).toThrow(
			/where the step-up starts/,
		);
		// The name is not a declaration: `mfa` saying nothing reaches nothing.
		expect(() =>
			resolverForTests(
				[requirement("mfa", { reach: new Set(["otp", "mfa"]), stepUpPage: page })],
				onIssuer,
			),
		).toThrow(RangeError);
		expect(
			resolverForTests(
				[
					requirement("second", {
						secondFactorAuthority: true,
						reach: new Set(["otp", "mfa"]),
						stepUpPage: page,
						remediations: ["second.step_up"],
					}),
				],
				onIssuer,
			)
				.get("second")
				?.reach.has("otp"),
		).toBe(true);
		const lifted = resolverForTests(
			[requirement("x", { reach: new Set(["risk-ok"]), stepUpPage: page })],
			{ allowAnyReach: true, ...onIssuer },
		);
		expect([...(lifted.get("x")?.reach ?? [])]).toEqual(["risk-ok"]);
		// Still sealed under the opt-out: a snapshot, not the contributor's Set.
		const sealed = lifted.get("x")?.reach as object;
		expect("add" in sealed).toBe(false);
	});

	it("holds the page to the issuer given, and an absolute page to its shape alone — resolved on itself — when none is", () => {
		const paged = requirement("x", {
			reach: new Set(["otp"]),
			stepUpPage: { url: "https://other.test/x", params: {} },
		});
		expect(() => anyReach([paged], ISSUER)).toThrow(RangeError);
		expect(anyReach([paged]).get("x")?.stepUpPage).toEqual({
			...paged.stepUpPage,
			href: "https://other.test/x",
		});
	});
});

describe("sealRegisteredReach — a registered reach, read once after the name-keyed pass and sealed on the copy", () => {
	// `"none"` rather than `undefined`: a default parameter would replace an
	// explicit `undefined` with the page.
	const raw = (
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

	/** `raw`'s requirement as registration copies it: what the seal is handed. */
	const requirement = (
		name: string,
		reach: unknown,
		page: SessionRequirement["stepUpPage"] | "none" = { url: "/x", params: {} },
	): RegisteredRequirement => registeredRequirement(raw(name, reach, page), ISSUER);

	/** A registered requirement that declares the second-factor authority, under a name that is not `mfa`. */
	const authority = (reach: unknown, name = "second"): RegisteredRequirement =>
		registeredRequirement({ ...raw(name, reach), secondFactorAuthority: true }, ISSUER);

	it("answers the reach as a set of its own, and lets the requirement that declares the second-factor authority reach the second-factor values, whatever its name", () => {
		const reach = new Set(["otp", "hwk", "mfa"]);
		const read = sealRegisteredReach(authority(reach));
		expect([...read]).toEqual(["otp", "hwk", "mfa"]);
		expect(read).not.toBe(reach);
		expect([...sealRegisteredReach(authority(new Set(["otp"]), "keys"))]).toEqual(["otp"]);
		expect(sealRegisteredReach(requirement("plain", new Set(), "none")).size).toBe(0);
	});

	it("refuses a non-empty reach from a requirement that does not declare the second-factor authority — in this release only the authority adds vouched values to a session — the one home of the rule boot, resolverForTests and the contract suite hold a reach to", () => {
		for (const name of ["risk", "consent", "x", "mfa"]) {
			expect(() => sealRegisteredReach(requirement(name, new Set(["risk-ok"]))), name).toThrow(
				RangeError,
			);
			expect(() => sealRegisteredReach(requirement(name, ["risk-ok"])), name).toThrow(
				/only the second-factor authority adds vouched values to a session/,
			);
			// Nothing reached: accepted, with or without a page.
			expect(sealRegisteredReach(requirement(name, new Set())).size, name).toBe(0);
		}
		// Saying it is not the authority is saying nothing.
		expect(() =>
			sealRegisteredReach(
				registeredRequirement(
					{ ...raw("risk", new Set(["risk-ok"])), secondFactorAuthority: false },
					ISSUER,
				),
			),
		).toThrow(/only the second-factor authority adds vouched values to a session/);
		// The page is still asked for first: a reach without one says so.
		expect(() => sealRegisteredReach(requirement("risk", new Set(["risk-ok"]), "none"))).toThrow(
			/where the step-up starts/,
		);
		// Boot's refusal and the contract suite's name no test remedy.
		expect(() => sealRegisteredReach(requirement("risk", new Set(["risk-ok"])))).not.toThrow(
			/allowAnyReach/,
		);
		expect(() => sealRegisteredReach(requirement("risk", new Set(["risk-ok"])))).toThrow(
			/so any other reach must be empty$/,
		);
		// And a registered copy that is refused is not sealed.
		const registered = requirement("risk", new Set(["risk-ok"]));
		expect(() => sealRegisteredReach(registered)).toThrow(RangeError);
		expect("add" in registered.reach).toBe(true);
		// The authority reaches what its factors do, a value of its own included.
		expect([...sealRegisteredReach(authority(new Set(["risk-ok"])))]).toEqual(["risk-ok"]);
	});

	it("holds a requirement named mfa that does not declare the second-factor authority to the rules of any other: no second-factor value, and nothing at all", () => {
		for (const reach of [["otp"], ["mfa"], ["otp", "mfa"], ["risk-ok"]]) {
			expect(() => sealRegisteredReach(requirement("mfa", new Set(reach))), String(reach)).toThrow(
				RangeError,
			);
		}
		expect(() => sealRegisteredReach(requirement("mfa", new Set(["otp"])))).toThrow(
			/a second-factor value only the second-factor authority may reach/,
		);
	});

	it("reads the getter once", () => {
		let reads = 0;
		const source = { ...raw("second", undefined), secondFactorAuthority: true };
		Object.defineProperty(source, "reach", {
			get() {
				reads++;
				return new Set(["risk-ok"]);
			},
		});
		sealRegisteredReach(registeredRequirement(source, ISSUER));
		expect(reads).toBe(1);
	});

	it("seals a registered copy on a frozen snapshot: read once, answered afterwards without the source, unchanged by a contributor mutating or swapping its Set", () => {
		let reads = 0;
		const live = new Set(["risk-ok"]);
		let current = live;
		const source = {
			name: "second",
			secondFactorAuthority: true,
			get reach() {
				reads++;
				return current;
			},
			stepUpPage: { url: "/second", params: {} },
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" as const }),
		} satisfies SessionRequirement;
		const registered = registeredRequirement(source, ISSUER);
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

	it("refuses a requirement that is not a registered copy: the declaration it weighs is the one registration read", () => {
		const source = { ...raw("second", new Set(["risk-ok"])), secondFactorAuthority: true };
		expect(() => sealRegisteredReach(source as never)).toThrow(/is not a registered copy/);
		// A copy of a registered one is not one either.
		expect(() => sealRegisteredReach({ ...authority(new Set(["risk-ok"])) } as never)).toThrow(
			/is not a registered copy/,
		);
	});

	it("accepts an iterable of values that is not a string — an array — answering a Set, and seals a registered copy on it", () => {
		expect([...sealRegisteredReach(authority(["risk-ok", "risk-ok"]))]).toEqual(["risk-ok"]);
		const registered = authority(["risk-ok"]);
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
		[
			"a second-factor value from a requirement that does not declare the authority",
			new Set(["otp"]),
		],
		["mfa from a requirement that does not declare the authority", new Set(["mfa"])],
	])("refuses a reach that is %s with a RangeError", (_label, reach) => {
		expect(() => sealRegisteredReach(requirement("risk", reach))).toThrow(RangeError);
	});

	it("holds the authority's reach to the rules every reach keeps: an iterable of non-empty strings, no primary's marker, a page when not empty", () => {
		for (const reach of [new Set(["pwd"]), new Set(["fed"]), new Set([""]), "otp"]) {
			expect(() => sealRegisteredReach(authority(reach)), String(reach)).toThrow(RangeError);
		}
		expect(() =>
			sealRegisteredReach(
				registeredRequirement(
					{ ...raw("second", new Set(["otp"]), "none"), secondFactorAuthority: true },
					ISSUER,
				),
			),
		).toThrow(/where the step-up starts/);
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
	it("RequirementInput is a session view, the requirement session, the carrier and now, and a verdict names no page", () => {
		expectTypeOf<RequirementInput["session"]>().toEqualTypeOf<SessionView | null>();
		expectTypeOf<SessionView>().toEqualTypeOf<{
			readonly sid: string;
			readonly sub: string;
			readonly authTime: Date;
			readonly expiresAt: Date;
			readonly enrollmentFacts?: SessionEnrollmentFacts;
		}>();
		expectTypeOf<SessionEnrollmentFacts>().toEqualTypeOf<{
			readonly witness: MfaEnrollmentWitness;
			readonly mailAddress: "none" | "address" | "unreadable";
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

	it("a request's action is a name, or a remediation core issued: a registered action's object is not one", () => {
		expectTypeOf<AdmissionRequest["action"]>().toEqualTypeOf<string | IssuedRemediationAction>();
		expectTypeOf<AdmissionAction>().not.toMatchTypeOf<AdmissionRequest["action"]>();
		expectTypeOf<IssuedRemediationAction>().toMatchTypeOf<AdmissionAction>();
		expect(true).toBe(true);
	});

	it("PrimaryAuthentication carries what a login path records and the enrollment facts core derives, never a method and amr of its own", () => {
		expectTypeOf<PrimaryAuthentication>().toEqualTypeOf<{
			readonly subject: string;
			readonly user: Readonly<Record<string, unknown>>;
			readonly claims: UserSessionClaims;
			readonly recorded: RecordedAuthentication;
			readonly enrollmentFacts: SessionEnrollmentFacts;
			readonly authTime: Date;
			readonly redirectTo: string | undefined;
			readonly request: { readonly ip?: string; readonly userAgent?: string };
		}>();
		expect(true).toBe(true);
	});
});

describe("the refusals and the read-only view, each driven", () => {
	const authority = {
		name: "second",
		secondFactorAuthority: true,
		reach: new Set(["otp", "mfa"]),
		stepUpPage: { url: "/second", params: {} },
		remediations: ["second.step_up"],
		hintKeys: [],
		admit: async () => ({ outcome: "met" as const }),
	} satisfies SessionRequirement;

	it("a sealed reach answers the set algebra over a copy of its own — never the private set — and names itself", () => {
		const reach = resolverForTests([authority], { issuer: ISSUER }).get("second")
			?.reach as ReadonlySet<string>;
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
					resolverForTests([{ ...authority, name: "x", remediations: [], reach } as never], {
						allowAnyReach: true,
						issuer: ISSUER,
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
