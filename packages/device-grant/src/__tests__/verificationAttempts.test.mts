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
 * The verification endpoint's own attempt limit: `device-grant.rateLimit`
 * read as the spec the attempt guard counts against, and the
 * `device_verification` prefix the module claims of the rate limiter with no
 * budget, since no limiter decides the limit RFC 8628 §5.1 sizes the user
 * code against.
 */

import { describe, expect, it } from "vitest";
import { deviceAuthorizationGrantModule } from "#/module.mjs";
import {
	DEVICE_VERIFICATION_ATTEMPT_TAG,
	readVerificationAttemptSpec,
} from "#/verificationAttempts.mjs";

describe("readVerificationAttemptSpec", () => {
	it("is device-grant.rateLimit, as written", () => {
		expect(readVerificationAttemptSpec({ rateLimit: { limit: 5, windowSeconds: 300 } })).toEqual({
			limit: 5,
			windowSeconds: 300,
		});
	});

	it("takes a day, the longest window a counter takes", () => {
		expect(readVerificationAttemptSpec({ rateLimit: { limit: 5, windowSeconds: 86_400 } })).toEqual(
			{ limit: 5, windowSeconds: 86_400 },
		);
	});

	it("reads the key as its schema does: a numeric string is its number", () => {
		expect(
			readVerificationAttemptSpec({ rateLimit: { limit: "5", windowSeconds: " 300 " } }),
		).toEqual({ limit: 5, windowSeconds: 300 });
	});

	it("refuses a missing or unusable device-grant.rateLimit, naming the key", () => {
		for (const section of [
			undefined,
			{},
			...[
				{ limit: 5, windowSeconds: 0 },
				{ limit: 5, windowSeconds: 86_401 },
				{ limit: 5, windowSeconds: 1.5 },
				{ limit: 0, windowSeconds: 300 },
				{ limit: 2.5, windowSeconds: 300 },
				{ limit: -5, windowSeconds: 300 },
				{ limit: Number.NaN, windowSeconds: 300 },
				{ limit: "five", windowSeconds: 300 },
				{ limit: true, windowSeconds: 300 },
				{ limit: 5 },
				null,
				"5/300",
			].map((rateLimit) => ({ rateLimit })),
		]) {
			expect(() => readVerificationAttemptSpec(section), JSON.stringify(section)).toThrow(
				/^device-grant\.rateLimit must be/,
			);
		}
	});

	it("says what it was given, with each value's type", () => {
		expect(() =>
			readVerificationAttemptSpec({ rateLimit: { limit: "five", windowSeconds: 300 } }),
		).toThrow(/\(got limit "five", windowSeconds 300\)$/);
	});
});

describe("the device-grant module and the rate limiter", () => {
	it("counts under the prefix the verification endpoint always keyed", () => {
		expect(DEVICE_VERIFICATION_ATTEMPT_TAG).toBe("device_verification");
	});

	it("claims the device_verification prefix with no budget: the verification's limit is its own", async () => {
		const claim =
			deviceAuthorizationGrantModule.contributes?.rateLimitBudgets?.[
				DEVICE_VERIFICATION_ATTEMPT_TAG
			];
		expect(claim).toBeTypeOf("function");
		expect(
			await claim?.({ section: { rateLimit: { limit: 7, windowSeconds: 60 } } } as never),
		).toBeNull();
	});

	it("reads the attemptCounter slot and the deployment mode, and no contributed budget", () => {
		expect(deviceAuthorizationGrantModule.optional).toContain("attemptCounter");
		expect(deviceAuthorizationGrantModule.requires).toContain("deploymentMode");
		expect(deviceAuthorizationGrantModule.requires).not.toContain("rateLimitBudgetResolver");
	});

	it("keeps the rate limiter optional, for /oauth/device_authorization alone", () => {
		expect(deviceAuthorizationGrantModule.optional).toContain("rateLimiter");
		expect(deviceAuthorizationGrantModule.requires).not.toContain("rateLimiter");
	});
});
