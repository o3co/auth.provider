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
 * What a refusal of a configured budget shows of the value it was given.
 *
 * The refusal names the key and shows each value with its type, so a string
 * is not mistaken for the number it spells. A hand-built config can carry
 * anything, including values JSON cannot write: those are still shown, still
 * under the key's name, and never as a function's source text.
 */

import { describe, expect, it } from "vitest";
import { requireUsableConfiguredRateLimitSpec } from "#/ratelimit/usableSpec.mjs";

const refusalOf = (limit: unknown): string => {
	try {
		requireUsableConfiguredRateLimitSpec("webauthn.rateLimit.authenticationOptions", {
			limit,
			windowSeconds: 60,
		});
	} catch (err) {
		expect(err).toBeInstanceOf(RangeError);
		return (err as Error).message;
	}
	throw new Error("expected a refusal");
};

describe("requireUsableConfiguredRateLimitSpec — what the refusal shows", () => {
	it("shows a string quoted and a number as it prints", () => {
		expect(refusalOf("thirty")).toMatch(/\(got limit "thirty", windowSeconds 60\)$/);
		expect(refusalOf(0)).toMatch(/\(got limit 0, windowSeconds 60\)$/);
		expect(refusalOf(Number.NaN)).toMatch(/\(got limit NaN, windowSeconds 60\)$/);
	});

	it("shows a BigInt as one, rather than as the number it would be mistaken for", () => {
		// JSON.stringify throws on a BigInt, and String() shows 10n as 10.
		expect(refusalOf(10n)).toMatch(/^webauthn\.rateLimit\.authenticationOptions must be/);
		expect(refusalOf(10n)).toMatch(/\(got limit 10n, windowSeconds 60\)$/);
	});

	it("shows a value JSON.stringify throws on, still naming the key", () => {
		const circular: Record<string, unknown> = {};
		circular.self = circular;
		expect(refusalOf(circular)).toMatch(/^webauthn\.rateLimit\.authenticationOptions must be/);
		expect(refusalOf(circular)).toMatch(/\(got limit \[object Object\], windowSeconds 60\)$/);
	});

	it("shows a value JSON.stringify answers undefined for", () => {
		expect(refusalOf(Symbol("thirty"))).toMatch(
			/\(got limit Symbol\(thirty\), windowSeconds 60\)$/,
		);
		expect(refusalOf({ toJSON: () => undefined })).toMatch(
			/\(got limit \[object Object\], windowSeconds 60\)$/,
		);
	});

	it("shows a function as one, never its source", () => {
		const message = refusalOf(function secretLimit() {
			return "s3cret";
		});
		expect(message).toMatch(/\(got limit \[function\], windowSeconds 60\)$/);
		expect(message).not.toContain("s3cret");
	});
});
