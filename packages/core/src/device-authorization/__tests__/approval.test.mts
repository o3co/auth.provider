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
 * `recordableDeviceApproval`: what every bundled `DeviceCodeStore` records of
 * an approval's authentication. The contract suite holds the stores to it;
 * this file holds the answer itself.
 */

import { describe, expect, it } from "vitest";
import { recordableDeviceApproval } from "#/device-authorization/approval.mjs";
import { DEFAULT_CLOCK_SKEW_MS } from "#/jwt/verify.mjs";

const NOW = 1_800_000_000_000;

describe("recordableDeviceApproval", () => {
	it("answers absent for absent, never a value of its own", () => {
		expect(recordableDeviceApproval({}, NOW)).toStrictEqual({
			amr: undefined,
			authTimeMs: undefined,
		});
	});

	it("answers the amr as a frozen copy, not the caller's array", () => {
		const amr = ["pwd", "otp", "mfa"];
		const recorded = recordableDeviceApproval({ amr }, NOW);
		expect(recorded.amr).toEqual(["pwd", "otp", "mfa"]);
		expect(recorded.amr).not.toBe(amr);
		expect(Object.isFrozen(recorded.amr)).toBe(true);
	});

	it("answers the instant in epoch milliseconds, no later than the clock", () => {
		expect(recordableDeviceApproval({ authTime: new Date(NOW - 1) }, NOW).authTimeMs).toBe(NOW - 1);
		expect(recordableDeviceApproval({ authTime: new Date(0) }, NOW).authTimeMs).toBe(0);
		expect(
			recordableDeviceApproval({ authTime: new Date(NOW + DEFAULT_CLOCK_SKEW_MS) }, NOW).authTimeMs,
		).toBe(NOW);
		expect(recordableDeviceApproval({ authTime: new Date(NOW) }, NOW + 0.75).authTimeMs).toBe(NOW);
	});

	it("refuses an amr that is not a non-empty list of non-empty strings", () => {
		for (const amr of [[], [""], [1], "pwd", null] as unknown as ReadonlyArray<readonly string[]>) {
			expect(() => recordableDeviceApproval({ amr }, NOW), String(amr)).toThrow(RangeError);
		}
	});

	it("refuses an instant that is not a valid Date, is before the epoch, or is further ahead than the skew", () => {
		for (const authTime of [
			new Date(Number.NaN),
			new Date(-1),
			new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 1),
			NOW,
			null,
		] as unknown as ReadonlyArray<Date>) {
			expect(() => recordableDeviceApproval({ authTime }, NOW), String(authTime)).toThrow(
				RangeError,
			);
		}
	});
});
