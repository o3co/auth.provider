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
 * A configured lockout policy: the store's port check, then the floor a
 * deployment's policy is held to.
 */

import { describe, expect, it } from "vitest";
import * as core from "#/index.mjs";
import {
	checkConfiguredMfaLockoutPolicy,
	checkMfaLockoutPolicy,
	MFA_LOCKOUT_MAX_BACKOFF_SECONDS,
	MFA_LOCKOUT_MIN_HARD_LIMIT,
	type MfaLockoutPolicy,
} from "#/mfa/transactionStore.mjs";

/** The MFA ADR's D19 defaults. */
const DEFAULTS: MfaLockoutPolicy = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
};

describe("checkConfiguredMfaLockoutPolicy — a lockout policy a deployment may configure", () => {
	it("is exported from core with its floor, 10", () => {
		expect(core.checkConfiguredMfaLockoutPolicy).toBe(checkConfiguredMfaLockoutPolicy);
		expect(core.MFA_LOCKOUT_MIN_HARD_LIMIT).toBe(10);
		expect(MFA_LOCKOUT_MIN_HARD_LIMIT).toBe(10);
	});

	it("answers the checked copy of the defaults, and of a policy at the floor with threshold one below", () => {
		expect(checkConfiguredMfaLockoutPolicy(DEFAULTS)).toEqual(DEFAULTS);
		const atTheFloor = { ...DEFAULTS, threshold: 9, hardLimit: 10 };
		const checked = checkConfiguredMfaLockoutPolicy(atTheFloor, "mfa.lockout");
		expect(checked).toEqual(atTheFloor);
		expect(checked).not.toBe(atTheFloor);
		expect(Object.isFrozen(checked)).toBe(true);
	});

	it("refuses a hardLimit below 10, naming the path and the reason: the limit attempt holds whatever its outcome", () => {
		for (const hardLimit of [1, 2, 6, 9]) {
			const policy = { ...DEFAULTS, threshold: 1, hardLimit };
			expect(
				() => checkConfiguredMfaLockoutPolicy(policy, "mfa.lockout"),
				String(hardLimit),
			).toThrow(RangeError);
			expect(() => checkConfiguredMfaLockoutPolicy(policy, "mfa.lockout")).toThrow(
				/^mfa\.lockout\.hardLimit must be at least 10: .*whatever its outcome.*correct code/,
			);
		}
	});

	it("refuses a hardLimit equal to threshold, naming the path and the reason: the backoff acts first", () => {
		for (const limit of [10, 50]) {
			const policy = { ...DEFAULTS, threshold: limit, hardLimit: limit };
			expect(() => checkConfiguredMfaLockoutPolicy(policy, "mfa.lockout"), String(limit)).toThrow(
				/^mfa\.lockout\.hardLimit must be above mfa\.lockout\.threshold: .*backoff/,
			);
		}
	});

	it("refuses a hardLimit below threshold through the store's port check", () => {
		expect(() =>
			checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, threshold: 50, hardLimit: 10 }),
		).toThrow(/^mfa\.lockout\.threshold must be at most mfa\.lockout\.hardLimit$/);
	});

	it("answers with the store's port check where both checks would refuse", () => {
		for (const bad of [{ threshold: 1, hardLimit: 9.5 }, { hardLimit: Number.NaN }]) {
			expect(
				() => checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, ...bad }),
				String(bad.hardLimit),
			).toThrow(/^mfa\.lockout\.hardLimit must be a positive whole number$/);
		}
		expect(() =>
			checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, threshold: 50, hardLimit: 9 }),
		).toThrow(/^mfa\.lockout\.threshold must be at most mfa\.lockout\.hardLimit$/);
	});

	it("runs the store's port check first: a hardLimit above 100 and a policy that is no object are its refusals", () => {
		expect(() => checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, hardLimit: 101 })).toThrow(
			/^mfa\.lockout\.hardLimit must be at most 100/,
		);
		expect(() => checkConfiguredMfaLockoutPolicy(null as never)).toThrow(
			/^mfa\.lockout must be an object$/,
		);
	});

	it("exports the longest backoff a configured policy may set, a week", () => {
		expect(core.MFA_LOCKOUT_MAX_BACKOFF_SECONDS).toBe(604_800);
		expect(MFA_LOCKOUT_MAX_BACKOFF_SECONDS).toBe(604_800);
	});

	it("admits a maxSeconds of a week", () => {
		const aWeek = { ...DEFAULTS, maxSeconds: 604_800 };
		expect(checkConfiguredMfaLockoutPolicy(aWeek)).toEqual(aWeek);
	});

	it("refuses a maxSeconds longer than a week, naming the path and the reason: the backoff would outlast the week's failures", () => {
		for (const maxSeconds of [604_801, 2_592_000]) {
			expect(() =>
				checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, maxSeconds }, "mfa.lockout"),
			).toThrow(/^mfa\.lockout\.maxSeconds must be at most 604800 \(a week\): .*week.*outlast/);
		}
	});

	it("answers with the store's port check where the port check refuses a maxSeconds longer than a week as well", () => {
		expect(() =>
			checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, baseSeconds: 700_000, maxSeconds: 650_000 }),
		).toThrow(/^mfa\.lockout\.maxSeconds must be at least mfa\.lockout\.baseSeconds$/);
		expect(() => checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, maxSeconds: 604_801.5 })).toThrow(
			/^mfa\.lockout\.maxSeconds must be a positive whole number$/,
		);
		expect(() => checkConfiguredMfaLockoutPolicy({ ...DEFAULTS, maxSeconds: 9e12 })).toThrow(
			/^mfa\.lockout\.maxSeconds must end within the Date range$/,
		);
	});

	it("names the path it is given", () => {
		expect(() =>
			checkConfiguredMfaLockoutPolicy(
				{ ...DEFAULTS, threshold: 1, hardLimit: 5 },
				"custom.lockout",
			),
		).toThrow(/^custom\.lockout\.hardLimit must be at least 10/);
	});
});

describe("checkMfaLockoutPolicy — the store's port check", () => {
	it("keeps admitting a hardLimit below the configured floor, and one equal to threshold", () => {
		const small = { ...DEFAULTS, threshold: 2, hardLimit: 2 };
		expect(checkMfaLockoutPolicy(small)).toEqual(small);
	});
});
