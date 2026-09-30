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
 * The contract suite every requirement's tests run (the session-admission
 * ADR's D3): a well-formed fixture passes every case, and each way a
 * requirement can break the contract fails the case that names it.
 */

import { describe, expect, it } from "vitest";
import { passwordPrimary } from "#/session-admission/admit.mjs";
import type {
	RequirementInterruption,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import {
	type RequirementContractInput,
	sessionRequirementContract,
} from "#/session-admission/testing/requirement.contract.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");
const ISSUER = "https://auth.test";

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
			"name equals its key, and a fixture never declares the second-factor authority",
			"reach holds non-empty strings, no primary's marker, no second-factor value unless the requirement declares the second-factor authority, and — in this release — nothing at all unless it does; stepUpPage is set when reach is not empty, and is valid when set",
			"remediations are the requirement's own routes — <name>.<route> — each once, none a consumer's action in ADMISSION_ACTIONS",
			"hintKeys are hint names",
			"admit is never called with a dead session",
			"admit is never called for a remediation action",
			"admit answers a verdict, and a step_up only when stepUpPage is set",
			"an outage is thrown, never answered met",
			"an interruption's body carries none of the reserved keys, and no hint value carries an address",
		]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});
});

describe("sessionRequirementContract — each way a requirement can break it", () => {
	it("a name that is not its key, or a fixture that declares the second-factor authority; a fixture named mfa that does not declare it, or a requirement under test that is not a fixture and declares it, passes", async () => {
		expect(await failing({ build: () => fixture({ name: "other" }) })).toContain(
			"name equals its key, and a fixture never declares the second-factor authority",
		);
		expect(await failing({ build: () => fixture({ secondFactorAuthority: true }) })).toContain(
			"name equals its key, and a fixture never declares the second-factor authority",
		);
		expect(
			await failing({
				key: "mfa",
				build: () => fixture({ name: "mfa", remediations: ["mfa.step_up"] }),
			}),
		).not.toContain(
			"name equals its key, and a fixture never declares the second-factor authority",
		);
		// The declaration is read as registration reads it: one that is neither
		// true, false nor absent does not register.
		expect(
			await failing({ build: () => fixture({ secondFactorAuthority: "yes" as never }) }),
		).toContain("name equals its key, and a fixture never declares the second-factor authority");
		// A requirement under test that is not a fixture may declare it.
		expect(
			await failing({ fixture: false, build: () => fixture({ secondFactorAuthority: true }) }),
		).not.toContain(
			"name equals its key, and a fixture never declares the second-factor authority",
		);
	});

	it("a reach with a reserved value under another name, a primary's marker, or a page missing", async () => {
		const reach =
			"reach holds non-empty strings, no primary's marker, no second-factor value unless the requirement declares the second-factor authority, and — in this release — nothing at all unless it does; stepUpPage is set when reach is not empty, and is valid when set";
		expect(await failing({ build: () => fixture({ reach: new Set(["otp"]) }) })).toContain(reach);
		expect(await failing({ build: () => fixture({ reach: new Set(["pwd"]) }) })).toContain(reach);
		expect(await failing({ build: () => fixture({ reach: new Set(["fixture-ok"]) }) })).toContain(
			reach,
		);
		expect(
			await failing({
				build: () =>
					fixture({
						reach: new Set(["fixture-ok"]),
						stepUpPage: { url: "https://evil.test/x", params: {} },
					}),
			}),
		).toContain(reach);
		// A page with an empty reach is allowed: a step-up that adds no value.
		expect(
			await failing({
				build: () => fixture({ stepUpPage: { url: "/x", params: {} } }),
			}),
		).not.toContain(reach);
	});

	it("a reach from a requirement that does not declare the second-factor authority — one named mfa among them: only the authority adds vouched values in this release", async () => {
		const only =
			"reach holds non-empty strings, no primary's marker, no second-factor value unless the requirement declares the second-factor authority, and — in this release — nothing at all unless it does; stepUpPage is set when reach is not empty, and is valid when set";
		expect(
			await failing({
				build: () =>
					fixture({
						reach: new Set(["fixture-ok"]),
						stepUpPage: { url: "/fixture-a", params: {} },
					}),
			}),
		).toContain(only);
		expect(await failing({ build: () => fixture() })).not.toContain(only);
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
		).toContain(only);
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
		).not.toContain(only);
	});

	it("remediations that are not names, are not the requirement's own routes, or repeat", async () => {
		const remediations =
			"remediations are the requirement's own routes — <name>.<route> — each once, none a consumer's action in ADMISSION_ACTIONS";
		expect(await failing({ build: () => fixture({ remediations: [""] }) })).toContain(remediations);
		expect(await failing({ build: () => fixture({ remediations: ["a", "a"] }) })).toContain(
			remediations,
		);
		expect(
			await failing({ build: () => fixture({ remediations: ["oauth.authorize"] }) }),
		).toContain(remediations);
		expect(
			await failing({
				build: () => fixture({ remediations: ["fixture-a.step_up", "fixture-a.step_up"] }),
			}),
		).toContain(remediations);
	});

	it("a primary handed in that the fixture's admitPrimary establishes for — the interruption case must not pass vacuously", async () => {
		expect(
			await failing({ build: () => fixture({ admitPrimary: async () => "establish" }) }),
		).toContain(
			"an interruption's body carries none of the reserved keys, and no hint value carries an address",
		);
	});

	it("a remediation that is a consumer's action, under the requirement's own namespace", async () => {
		expect(
			await failing({
				key: "oauth",
				build: () => fixture({ name: "oauth", remediations: ["oauth.authorize"] }),
			}),
		).toContain(
			"remediations are the requirement's own routes — <name>.<route> — each once, none a consumer's action in ADMISSION_ACTIONS",
		);
	});

	it("a hint key that is reserved", async () => {
		expect(await failing({ build: () => fixture({ hintKeys: ["email"] }) })).toContain(
			"hintKeys are hint names",
		);
	});

	it("an outage answered met", async () => {
		expect(await failing({ withOutage: () => fixture() })).toContain(
			"an outage is thrown, never answered met",
		);
	});

	it("a step_up from a requirement without a page, and a verdict that is not one", async () => {
		const verdict = "admit answers a verdict, and a step_up only when stepUpPage is set";
		expect(
			await failing({
				build: () =>
					fixture({
						reach: new Set(),
						stepUpPage: undefined,
						admit: async () => ({ outcome: "step_up", whenStillUnmet: "unmet" }),
					}),
			}),
		).toContain(verdict);
		expect(
			await failing({
				build: () => fixture({ admit: async () => ({ outcome: "maybe" }) as never }),
			}),
		).toContain(verdict);
	});

	it("an interruption whose body carries a reserved key, or a hint carrying an address", async () => {
		const body =
			"an interruption's body carries none of the reserved keys, and no hint value carries an address";
		expect(
			await failing({
				build: () =>
					fixture({
						admitPrimary: async () =>
							interruption({ error: "fixture_required", user: { id: "user-1" } }),
					}),
			}),
		).toContain(body);
		expect(
			await failing({
				build: () =>
					fixture({
						admitPrimary: async () =>
							interruption({ error: "fixture_required", hints: { level: "alice@example.com" } }),
					}),
			}),
		).toContain(body);
	});

	it("skips the outage and interruption cases when the input offers neither", async () => {
		const names = sessionRequirementContract(
			input({ withOutage: undefined, primary: undefined }),
		).map((c) => c.name);
		expect(names).not.toContain("an outage is thrown, never answered met");
		expect(names).not.toContain(
			"an interruption's body carries none of the reserved keys, and no hint value carries an address",
		);
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
			"an interruption's body carries none of the reserved keys, and no hint value carries an address",
		);
	});
});
