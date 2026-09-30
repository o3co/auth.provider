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
 * The actions admission is asked about: the grades core owns, what a
 * registration may declare, and the actions a test registers on
 * `resolverForTests`.
 */

import { describe, expect, it } from "vitest";
import {
	ADMISSION_GRADES,
	admissionActionProblem,
	registeredAdmissionAction,
} from "#/session-admission/actions.mjs";
import type { SessionRequirement } from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";

const requirement = (name: string, over: Partial<SessionRequirement> = {}): SessionRequirement => ({
	name,
	reach: new Set(),
	stepUpPage: undefined,
	remediations: [],
	hintKeys: [],
	admit: async () => ({ outcome: "met" }),
	...over,
});

describe("the grades — a closed vocabulary core owns", () => {
	it("are use, grants_nothing, credential_change and remediation, frozen", () => {
		expect(ADMISSION_GRADES).toEqual(["use", "grants_nothing", "credential_change", "remediation"]);
		expect(Object.isFrozen(ADMISSION_GRADES)).toBe(true);
	});
});

describe("registeredAdmissionAction — an action as it is registered", () => {
	it("answers the frozen { name, grade }, for every grade an action may register with", () => {
		for (const grade of ["use", "grants_nothing", "credential_change"] as const) {
			const action = registeredAdmissionAction("acme.export", { grade });
			expect(action).toEqual({ name: "acme.export", grade });
			expect(Object.isFrozen(action)).toBe(true);
		}
	});

	it("reads the grade once: a getter answering differently to a second read registers what it answered first", () => {
		let reads = 0;
		const declaration = {
			get grade() {
				reads++;
				return reads === 1 ? "credential_change" : "grants_nothing";
			},
		};
		expect(registeredAdmissionAction("acme.export", declaration).grade).toBe("credential_change");
		expect(reads).toBe(1);
	});

	it("admits two lower-case identifiers joined by a dot, each part a letter then letters, digits or underscores", () => {
		for (const name of [
			"a.b",
			"acme.export",
			"a_b.c_d",
			"acme_pay.refund_all",
			"a1.b2",
			"v2_api.read_3",
			"x.y_",
			"x_.y",
		]) {
			expect(admissionActionProblem(name, { grade: "use" }), name).toBeUndefined();
		}
	});

	it("refuses a name outside the grammar, naming it", () => {
		for (const name of [
			"",
			"oauth",
			"oauth.",
			".authorize",
			"Oauth.authorize",
			"oauth.Authorize",
			"oauth.authorize.again",
			"federation-grants.connect",
			"1oauth.authorize",
			"oauth.1authorize",
			"oauth .authorize",
			"oauth.authorize\n",
		]) {
			expect(() => registeredAdmissionAction(name, { grade: "use" }), JSON.stringify(name)).toThrow(
				RangeError,
			);
			expect(admissionActionProblem(name, { grade: "use" }), JSON.stringify(name)).toContain(
				JSON.stringify(name),
			);
		}
	});

	it("refuses remediation, which only a requirement declares, and any grade outside the grades", () => {
		expect(() => registeredAdmissionAction("acme.export", { grade: "remediation" })).toThrow(
			/remediation is not an action's grade/,
		);
		for (const grade of ["read", "USE", "", undefined, null, 1, ["use"]]) {
			expect(
				() => registeredAdmissionAction("acme.export", { grade }),
				JSON.stringify(grade),
			).toThrow(/grade must be one of use, grants_nothing, credential_change/);
		}
	});

	it("refuses a declaration that is not an object", () => {
		for (const declaration of [null, undefined, "use", 1, ["use"]]) {
			expect(
				() => registeredAdmissionAction("acme.export", declaration),
				JSON.stringify(declaration),
			).toThrow(/a declaration is an object/);
		}
	});
});

describe("resolverForTests — the actions a test registers", () => {
	it("answers each registered action by its name, and nothing for a name not registered", () => {
		const resolver = resolverForTests([], {
			actions: { "acme.export": { grade: "use" }, "acme.peek": { grade: "grants_nothing" } },
		});
		expect(resolver.action("acme.export")).toEqual({ name: "acme.export", grade: "use" });
		expect(resolver.action("acme.peek")).toEqual({ name: "acme.peek", grade: "grants_nothing" });
		expect(resolver.action("acme.other")).toBeUndefined();
		expect(resolverForTests([]).action("acme.export")).toBeUndefined();
	});

	it("refuses an action registration refuses", () => {
		expect(() =>
			resolverForTests([], { actions: { "acme.export": { grade: "remediation" as never } } }),
		).toThrow(RangeError);
		expect(() => resolverForTests([], { actions: { Export: { grade: "use" } } })).toThrow(
			RangeError,
		);
	});

	it("refuses a requirement whose remediation is a registered action's name: registered as a remediation it would skip every requirement for that action", () => {
		expect(() =>
			resolverForTests([requirement("acme", { remediations: ["acme.export"] })], {
				actions: { "acme.export": { grade: "use" } },
			}),
		).toThrow(/acme\.export/);
		expect(
			resolverForTests([requirement("acme", { remediations: ["acme.step_up"] })], {
				actions: { "acme.export": { grade: "use" } },
			}).get("acme")?.remediations,
		).toEqual(["acme.step_up"]);
	});
});
