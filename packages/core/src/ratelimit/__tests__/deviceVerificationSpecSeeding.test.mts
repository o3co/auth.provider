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
 * `device_verification` was "present", not "5 attempts".
 *
 * The verification endpoint keys its budget `device_verification:user:<sub>`
 * and both bundled adapters resolve a spec by prefix, falling back to the
 * adapter's `defaultLimit` of 60/60s. Nothing seeded a `device_verification`
 * spec, so the effective budget was twelve times what the boot refusal
 * reasons from ("RFC 8628 §5.1 ... only allow 5 attempts"), and the key the
 * package README told operators to set did not exist.
 *
 * Same fix `login` got in #270: one config key that is the source of truth
 * (`oauth.deviceAuthorization.rateLimit`), seeded into each adapter's
 * `limits` unless the operator declared that prefix explicitly.
 */

import { describe, expect, it } from "vitest";
import {
	DEVICE_VERIFICATION_RATE_LIMIT_PREFIX,
	resolveDeviceVerificationLimitSpec,
} from "#/ratelimit/deviceVerificationSpec.mjs";
import { resolveSeededLimitSpecs } from "#/ratelimit/seededSpecs.mjs";

const configured = (limit: unknown, windowSeconds: unknown) => ({
	oauth: { deviceAuthorization: { rateLimit: { limit, windowSeconds } } },
});

describe("resolveDeviceVerificationLimitSpec", () => {
	it("names the prefix the verification endpoint keys on", () => {
		expect(DEVICE_VERIFICATION_RATE_LIMIT_PREFIX).toBe("device_verification");
	});

	it("seeds device_verification from oauth.deviceAuthorization.rateLimit", () => {
		const limits = resolveDeviceVerificationLimitSpec({}, configured(5, 300));
		expect(limits.device_verification).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("leaves an operator-declared device_verification spec alone", () => {
		// An explicit `limits.device_verification` is a statement about this
		// adapter; seeding over it would discard what the operator wrote.
		const limits = resolveDeviceVerificationLimitSpec(
			{ device_verification: { limit: 3, windowSeconds: 60 } },
			configured(5, 300),
		);
		expect(limits.device_verification).toEqual({ limit: 3, windowSeconds: 60 });
	});

	it("preserves every other prefix untouched", () => {
		const limits = resolveDeviceVerificationLimitSpec(
			{ token: { limit: 100, windowSeconds: 60 } },
			configured(5, 300),
		);
		expect(limits.token).toEqual({ limit: 100, windowSeconds: 60 });
		expect(limits.device_verification).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("does not seed when the config carries no usable spec", () => {
		// A hand-built config that never passed the schema: better to leave
		// the adapter's own default in place than to invent a limit.
		expect(resolveDeviceVerificationLimitSpec({}, {}).device_verification).toBeUndefined();
		expect(
			resolveDeviceVerificationLimitSpec({}, { oauth: {} }).device_verification,
		).toBeUndefined();
		for (const [limit, windowSeconds] of [
			[0, 300],
			[5, 0],
			[-1, 300],
			[2.5, 300],
			[5, 2.5],
			["5", 300],
			[5, "300"],
		]) {
			expect(
				resolveDeviceVerificationLimitSpec({}, configured(limit, windowSeconds))
					.device_verification,
				`limit=${String(limit)} windowSeconds=${String(windowSeconds)}`,
			).toBeUndefined();
		}
	});

	it("does not mutate the limits it was handed", () => {
		const input = {};
		resolveDeviceVerificationLimitSpec(input, configured(5, 300));
		expect(input).toEqual({});
	});
});

describe("resolveSeededLimitSpecs", () => {
	it("seeds every documented per-endpoint spec at once", () => {
		// The one call both adapter modules make, so a third seeded prefix
		// cannot land in one adapter and not the other.
		const limits = resolveSeededLimitSpecs(
			{},
			{
				rateLimit: { login: { windowMs: 900_000, limit: 20 } },
				...configured(5, 300),
			},
		);
		expect(limits.login).toEqual({ limit: 20, windowSeconds: 900 });
		expect(limits.device_verification).toEqual({ limit: 5, windowSeconds: 300 });
	});
});
