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
import type { Interruption, SessionRequirement } from "#/session-admission/requirement.mjs";
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
): Interruption => ({ open: async () => ({ status: 403, body }) as never });

/** A fixture that keeps the contract: reaches something, steps up to its page, interrupts a login, throws on an outage. */
const fixture = (over: Partial<SessionRequirement> = {}, down = false): SessionRequirement => ({
	name: "fixture-a",
	reach: new Set(["fixture-ok"]),
	stepUpPage: { url: "/fixture-a", params: {} },
	remediations: ["fixture-a.step_up"],
	hintKeys: ["level"],
	admit: async ({ authentication }) => {
		if (down) throw new Error("fixture store down");
		return authentication?.amr.includes("fixture-ok")
			? { outcome: "met" }
			: { outcome: "step_up", whenStillUnmet: "unmet" };
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

	it("names every case of D3", () => {
		expect(cases.map((c) => c.name)).toEqual([
			"name equals its key, and a fixture is never named mfa",
			"reach holds non-empty strings, no primary's marker, and no reserved value unless the name is mfa; stepUpPage is set exactly when reach is not empty, and is valid",
			"remediations are non-empty names, each once",
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
	it("a name that is not its key, or a fixture named mfa", async () => {
		expect(await failing({ build: () => fixture({ name: "other" }) })).toContain(
			"name equals its key, and a fixture is never named mfa",
		);
		expect(await failing({ key: "mfa", build: () => fixture({ name: "mfa" }) })).toContain(
			"name equals its key, and a fixture is never named mfa",
		);
	});

	it("a reach with a reserved value under another name, a primary's marker, or a page missing", async () => {
		const reach =
			"reach holds non-empty strings, no primary's marker, and no reserved value unless the name is mfa; stepUpPage is set exactly when reach is not empty, and is valid";
		expect(await failing({ build: () => fixture({ reach: new Set(["otp"]) }) })).toContain(reach);
		expect(await failing({ build: () => fixture({ reach: new Set(["pwd"]) }) })).toContain(reach);
		expect(await failing({ build: () => fixture({ stepUpPage: undefined }) })).toContain(reach);
		expect(
			await failing({
				build: () => fixture({ stepUpPage: { url: "https://evil.test/x", params: {} } }),
			}),
		).toContain(reach);
		expect(
			await failing({
				build: () => fixture({ reach: new Set(), stepUpPage: { url: "/x", params: {} } }),
			}),
		).toContain(reach);
	});

	it("remediations that are not names, are not the requirement's own routes, or repeat", async () => {
		const remediations =
			"remediations are the requirement's own routes — <name>.<route> — each once, none a bundled action of another grade";
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
