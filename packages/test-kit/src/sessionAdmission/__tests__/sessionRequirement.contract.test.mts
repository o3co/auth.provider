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
 * `sessionRequirementContract` run over a well-formed fixture, and the proof
 * that each case is not vacuous: a fixture broken one way each, refused by
 * the case that names what it breaks. The suite reads registration through
 * `resolverForTests` and builds admission's view of a live session by hand;
 * the last cases pin both to what core does.
 */

import {
	passwordPrimary,
	type RequirementInput,
	type RequirementInterruption,
	type SessionRequirement,
	type SessionView,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { type RequirementContractInput, sessionRequirementContract } from "#/index.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");
const ISSUER = "https://auth.test";

const RULES = {
	name: "name equals its key, and a fixture never declares the second-factor authority",
	reach:
		"reach holds non-empty strings, no primary's marker, no second-factor value unless the requirement declares the second-factor authority, and — in this release — nothing at all unless it does; stepUpPage is set when reach is not empty, and is valid when set",
	remediations: "remediations are the requirement's own routes — <name>.<route> — each once",
	hintKeys: "hintKeys are hint names",
	deadSession: "admit is never called with a dead session",
	remediationAction: "admit is never called for a remediation action",
	verdict: "admit answers a verdict, and a step_up only when stepUpPage is set",
	outage: "an outage is thrown, never answered met",
	interruption:
		"an interruption's body carries none of the reserved keys, and no hint value carries an address",
} as const;

const primary = () =>
	passwordPrimary({
		subject: "user-1",
		user: { id: "user-1" },
		claims: { email: "contract@example.test" },
		authTime: NOW,
		redirectTo: undefined,
		request: {},
	});

const interruption = (
	body: Record<string, unknown> = {
		error: "fixture_required",
		transaction: "dHgtMQ",
		expires_in: 60,
	},
): RequirementInterruption => ({ open: async () => ({ status: 403, body }) as never });

/** A fixture that keeps the contract: reaches nothing (only the second-factor authority does), admits, interrupts a login, throws on an outage. */
const fixture = (over: Partial<SessionRequirement> = {}, down = false): SessionRequirement => ({
	name: "fixture-a",
	reach: new Set(),
	stepUpPage: undefined,
	remediations: ["fixture-a.step_up"],
	hintKeys: ["level"],
	admit: async () => {
		if (down) throw new Error("fixture store down");
		return { outcome: "met" };
	},
	admitPrimary: async () => interruption(),
	...over,
});

const input = (over: Partial<RequirementContractInput> = {}): RequirementContractInput => ({
	key: "fixture-a",
	fixture: true,
	issuer: ISSUER,
	build: () => fixture(),
	withOutage: () => fixture({}, true),
	primary: primary(),
	...over,
});

/** The names of the cases `input` fails. */
const failing = async (over: Partial<RequirementContractInput>): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of sessionRequirementContract(input(over))) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

describe("sessionRequirementContract — a well-formed fixture", () => {
	const cases = sessionRequirementContract(input());

	it("names each of its cases, in order", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.name,
			RULES.reach,
			RULES.remediations,
			RULES.hintKeys,
			RULES.deadSession,
			RULES.remediationAction,
			RULES.verdict,
			RULES.outage,
			RULES.interruption,
		]);
	});

	for (const contractCase of cases) {
		it(contractCase.name, contractCase.run);
	}
});

describe("sessionRequirementContract — each way a requirement can break it", () => {
	it("a name that is not its key, or a fixture that declares the second-factor authority; a fixture named mfa that does not declare it, or a requirement under test that is not a fixture and declares it, passes", async () => {
		expect(await failing({ build: () => fixture({ name: "other" }) })).toContain(RULES.name);
		expect(await failing({ build: () => fixture({ secondFactorAuthority: true }) })).toContain(
			RULES.name,
		);
		expect(
			await failing({
				key: "mfa",
				build: () => fixture({ name: "mfa", remediations: ["mfa.step_up"] }),
			}),
		).not.toContain(RULES.name);
		// The declaration is read as registration reads it: one that is neither
		// true, false nor absent does not register.
		expect(
			await failing({ build: () => fixture({ secondFactorAuthority: "yes" as never }) }),
		).toContain(RULES.name);
		// A requirement under test that is not a fixture may declare it.
		expect(
			await failing({ fixture: false, build: () => fixture({ secondFactorAuthority: true }) }),
		).not.toContain(RULES.name);
	});

	it("a reach with a reserved value under another name, a primary's marker, or a page missing", async () => {
		expect(await failing({ build: () => fixture({ reach: new Set(["otp"]) }) })).toContain(
			RULES.reach,
		);
		expect(await failing({ build: () => fixture({ reach: new Set(["pwd"]) }) })).toContain(
			RULES.reach,
		);
		expect(await failing({ build: () => fixture({ reach: new Set(["fixture-ok"]) }) })).toContain(
			RULES.reach,
		);
		expect(
			await failing({
				build: () =>
					fixture({
						reach: new Set(["fixture-ok"]),
						stepUpPage: { url: "https://evil.test/x", params: {} },
					}),
			}),
		).toContain(RULES.reach);
		// A page with an empty reach is allowed: a step-up that adds no value.
		expect(
			await failing({
				build: () => fixture({ stepUpPage: { url: "/x", params: {} } }),
			}),
		).not.toContain(RULES.reach);
	});

	it("a reach from a requirement that does not declare the second-factor authority — one named mfa among them: only the authority adds vouched values in this release", async () => {
		expect(
			await failing({
				build: () =>
					fixture({
						reach: new Set(["fixture-ok"]),
						stepUpPage: { url: "/fixture-a", params: {} },
					}),
			}),
		).toContain(RULES.reach);
		expect(await failing({ build: () => fixture() })).not.toContain(RULES.reach);
		expect(
			await failing({
				key: "mfa",
				build: () =>
					fixture({
						name: "mfa",
						remediations: ["mfa.step_up"],
						reach: new Set(["otp", "mfa"]),
						stepUpPage: { url: "/mfa", params: {} },
					}),
			}),
		).toContain(RULES.reach);
		// The authority, under any name, reaches the second-factor values.
		expect(
			await failing({
				fixture: false,
				build: () =>
					fixture({
						secondFactorAuthority: true,
						reach: new Set(["otp", "mfa"]),
						stepUpPage: { url: "/fixture-a", params: {} },
					}),
			}),
		).not.toContain(RULES.reach);
	});

	it("a reach the seal refuses fails the reach case alone of the registration cases", async () => {
		const failed = await failing({ build: () => fixture({ reach: new Set(["otp"]) }) });
		expect(failed).toContain(RULES.reach);
		expect(failed).not.toContain(RULES.name);
		expect(failed).not.toContain(RULES.remediations);
		expect(failed).not.toContain(RULES.hintKeys);
	});

	it("remediations that are not names, are not the requirement's own routes, or repeat", async () => {
		expect(await failing({ build: () => fixture({ remediations: [""] }) })).toContain(
			RULES.remediations,
		);
		expect(await failing({ build: () => fixture({ remediations: ["a", "a"] }) })).toContain(
			RULES.remediations,
		);
		expect(
			await failing({ build: () => fixture({ remediations: ["oauth.authorize"] }) }),
		).toContain(RULES.remediations);
		expect(
			await failing({
				build: () => fixture({ remediations: ["fixture-a.step_up", "fixture-a.step_up"] }),
			}),
		).toContain(RULES.remediations);
	});

	it("a primary handed in that the fixture's admitPrimary establishes for — the interruption case must not pass vacuously", async () => {
		expect(
			await failing({ build: () => fixture({ admitPrimary: async () => "establish" }) }),
		).toContain(RULES.interruption);
	});

	it("a hint key that is reserved, or not a hint name", async () => {
		for (const hintKey of ["email", "Level", "", "a".repeat(33)]) {
			expect(await failing({ build: () => fixture({ hintKeys: [hintKey] }) }), hintKey).toContain(
				RULES.hintKeys,
			);
		}
	});

	it("an outage answered met", async () => {
		expect(await failing({ withOutage: () => fixture() })).toContain(RULES.outage);
	});

	it("a step_up from a requirement without a page, and a verdict that is not one", async () => {
		expect(
			await failing({
				build: () =>
					fixture({
						reach: new Set(),
						stepUpPage: undefined,
						admit: async () => ({ outcome: "step_up", whenStillUnmet: "unmet" }),
					}),
			}),
		).toContain(RULES.verdict);
		expect(
			await failing({
				build: () => fixture({ admit: async () => ({ outcome: "maybe" }) as never }),
			}),
		).toContain(RULES.verdict);
	});

	it("an interruption whose body carries a reserved key, or a hint carrying an address", async () => {
		expect(
			await failing({
				build: () =>
					fixture({
						admitPrimary: async () =>
							interruption({ error: "fixture_required", user: { id: "user-1" } }),
					}),
			}),
		).toContain(RULES.interruption);
		expect(
			await failing({
				build: () =>
					fixture({
						admitPrimary: async () =>
							interruption({ error: "fixture_required", hints: { level: "alice@example.com" } }),
					}),
			}),
		).toContain(RULES.interruption);
	});

	it("skips the outage and interruption cases when the input offers neither", async () => {
		const names = sessionRequirementContract(
			input({ withOutage: undefined, primary: undefined }),
		).map((c) => c.name);
		expect(names).not.toContain(RULES.outage);
		expect(names).not.toContain(RULES.interruption);
	});
});

describe("sessionRequirementContract — the paths a fixture's shape takes", () => {
	it("passes every case for a fixture with no remediation and no admitPrimary, and no issuer", async () => {
		const cases = sessionRequirementContract({
			key: "fixture-b",
			fixture: true,
			build: () => fixture({ name: "fixture-b", remediations: [], admitPrimary: undefined }),
		});
		for (const { name, run } of cases) await expect(run(), name).resolves.toBeUndefined();
	});

	it("passes every case with no issuer given, for a requirement that registers no step-up page", async () => {
		for (const { name, run } of sessionRequirementContract(input({ issuer: undefined }))) {
			await expect(run(), name).resolves.toBeUndefined();
		}
	});

	it("fails the interruption case, rather than passing it, when a primary is handed to a fixture that never interrupts", async () => {
		expect(await failing({ build: () => fixture({ admitPrimary: undefined }) })).toContain(
			RULES.interruption,
		);
	});
});

describe("sessionRequirementContract — the view it hands admit", () => {
	/** The sessions `admit` was handed while the case named `caseName` ran. */
	const viewsHandedIn = async (caseName: string): Promise<(SessionView | null)[]> => {
		const seen: (SessionView | null)[] = [];
		const cases = sessionRequirementContract(
			input({
				build: () =>
					fixture({
						admit: async (asked: RequirementInput) => {
							seen.push(asked.session);
							return { outcome: "met" };
						},
					}),
			}),
		);
		const found = cases.find((c) => c.name === caseName);
		expect(found, caseName).toBeDefined();
		await found?.run();
		return seen;
	};

	it("is the view admission hands a requirement over the same stores: frozen, the same members, no second factor recordable", async () => {
		// Admission's own view, from the case that admits a live session.
		const [admitted] = await viewsHandedIn(RULES.deadSession);
		// The view the suite builds itself, for each grade it asks about.
		const built = await viewsHandedIn(RULES.verdict);
		expect(admitted).not.toBeNull();
		expect(built.length).toBeGreaterThan(0);
		for (const view of [admitted, ...built]) {
			expect(view).not.toBeNull();
			expect(Object.isFrozen(view)).toBe(true);
			expect(Object.keys(view as SessionView).sort()).toEqual(
				Object.keys(admitted as SessionView).sort(),
			);
			expect(view?.sid).toBe(admitted?.sid);
			expect(view?.sub).toBe(admitted?.sub);
			expect(view?.authTime).toBeInstanceOf(Date);
			expect(view?.expiresAt).toBeInstanceOf(Date);
			expect(view?.secondFactorRecordable).toBe(false);
		}
	});
});
