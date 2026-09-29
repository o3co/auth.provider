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
 * HOTP and TOTP on `node:crypto` (the MFA ADR's F6, D22): RFC 6238 Appendix
 * B's vectors for the three algorithms, RFC 4226 Appendix D's for HOTP, and
 * the step matching a verification makes — `T - window … T + window`, and
 * only a step after the factor's `lastUsedStep` (RFC 6238 §5.2), so a code
 * used once is refused, and so is an older one never used once a newer one
 * was accepted.
 */

import { describe, expect, it } from "vitest";
import {
	hotp,
	matchTotpCode,
	TOTP_SECRET_BYTES,
	type TotpAlgorithm,
	totpStep,
} from "#/totp/rfc6238.mjs";

/** RFC 6238 Appendix B's seeds: the ASCII digits, repeated to each hash's output length. */
const SEEDS: Readonly<Record<TotpAlgorithm, Buffer>> = {
	SHA1: Buffer.from("12345678901234567890", "ascii"),
	SHA256: Buffer.from("12345678901234567890123456789012", "ascii"),
	SHA512: Buffer.from("1234567890123456789012345678901234567890123456789012345678901234", "ascii"),
};

/** RFC 6238 Appendix B: the time in seconds, then the 8-digit TOTP for SHA-1, SHA-256 and SHA-512 (T0 = 0, X = 30). */
const APPENDIX_B: readonly (readonly [number, string, string, string])[] = [
	[59, "94287082", "46119246", "90693936"],
	[1111111109, "07081804", "68084774", "25091201"],
	[1111111111, "14050471", "67062674", "99943326"],
	[1234567890, "89005924", "91819424", "93441116"],
	[2000000000, "69279037", "90698825", "38618901"],
	[20000000000, "65353130", "77737706", "47863826"],
];

/** RFC 4226 Appendix D: HOTP-SHA1, 6 digits, counters 0 to 9, over the 20-byte seed. */
const APPENDIX_D = [
	"755224",
	"287082",
	"359152",
	"969429",
	"338314",
	"254676",
	"287922",
	"162583",
	"399871",
	"520489",
];

describe("RFC 6238 Appendix B", () => {
	for (const [seconds, sha1, sha256, sha512] of APPENDIX_B) {
		const expected: Readonly<Record<TotpAlgorithm, string>> = {
			SHA1: sha1,
			SHA256: sha256,
			SHA512: sha512,
		};
		for (const algorithm of ["SHA1", "SHA256", "SHA512"] as const) {
			it(`${algorithm} at ${seconds} s is ${expected[algorithm]}`, () => {
				const step = totpStep(seconds * 1000, 30);
				expect(hotp(SEEDS[algorithm], step, { algorithm, digits: 8 })).toBe(expected[algorithm]);
				// The same code, as a verification finds it at that time.
				expect(
					matchTotpCode(expected[algorithm], {
						secret: SEEDS[algorithm],
						algorithm,
						digits: 8,
						period: 30,
						window: 0,
						nowMs: seconds * 1000,
					}),
				).toEqual({ outcome: "matched", step });
			});
		}
	}

	it("counts steps from the epoch: T = floor(seconds / 30)", () => {
		// The step values Appendix B tabulates in hex.
		expect(totpStep(59_000, 30)).toBe(0x1);
		expect(totpStep(1111111109_000, 30)).toBe(0x23523ec);
		expect(totpStep(1111111111_000, 30)).toBe(0x23523ed);
		expect(totpStep(1234567890_000, 30)).toBe(0x273ef07);
		expect(totpStep(2000000000_000, 30)).toBe(0x3f940aa);
		expect(totpStep(20000000000_000, 30)).toBe(0x27bc86aa);
	});

	it("uses a seed of each hash's output length (20, 32 and 64 bytes)", () => {
		expect(TOTP_SECRET_BYTES).toEqual({ SHA1: 20, SHA256: 32, SHA512: 64 });
		for (const algorithm of ["SHA1", "SHA256", "SHA512"] as const) {
			expect(SEEDS[algorithm].length).toBe(TOTP_SECRET_BYTES[algorithm]);
		}
	});
});

describe("RFC 4226 Appendix D (HOTP)", () => {
	APPENDIX_D.forEach((code, counter) => {
		it(`counter ${counter} is ${code}`, () => {
			expect(hotp(SEEDS.SHA1, counter, { algorithm: "SHA1", digits: 6 })).toBe(code);
		});
	});

	it("pads a short value with leading zeros to the digits asked for", () => {
		// 07081804 above has one; every code is exactly `digits` long.
		for (let counter = 0; counter < 200; counter++) {
			expect(hotp(SEEDS.SHA1, counter, { algorithm: "SHA1", digits: 7 })).toMatch(/^\d{7}$/);
		}
	});

	it("refuses a counter or a length it cannot compute", () => {
		const params = { algorithm: "SHA1", digits: 6 } as const;
		expect(() => hotp(SEEDS.SHA1, -1, params)).toThrow(RangeError);
		expect(() => hotp(SEEDS.SHA1, 1.5, params)).toThrow(RangeError);
		expect(() => hotp(SEEDS.SHA1, Number.MAX_SAFE_INTEGER + 1, params)).toThrow(RangeError);
		expect(() => hotp(SEEDS.SHA1, 0, { algorithm: "SHA1", digits: 5 })).toThrow(RangeError);
		expect(() => hotp(SEEDS.SHA1, 0, { algorithm: "SHA1", digits: 9 })).toThrow(RangeError);
		expect(() => hotp(Buffer.alloc(0), 0, params)).toThrow(RangeError);
		expect(() =>
			hotp(SEEDS.SHA1, 0, { algorithm: "MD5" as unknown as TotpAlgorithm, digits: 6 }),
		).toThrow(RangeError);
	});

	it("refuses a time or a period it cannot step", () => {
		expect(() => totpStep(-1, 30)).toThrow(RangeError);
		expect(() => totpStep(Number.NaN, 30)).toThrow(RangeError);
		expect(() => totpStep(Number.POSITIVE_INFINITY, 30)).toThrow(RangeError);
		expect(() => totpStep(0, 0)).toThrow(RangeError);
		expect(() => totpStep(0, 1.5)).toThrow(RangeError);
	});
});

describe("matching a code against the window", () => {
	const period = 30;
	const T = 50_000_000;
	/** Ten seconds into step T. */
	const nowMs = T * period * 1000 + 10_000;
	const secret = SEEDS.SHA1;
	const codeAt = (step: number) => hotp(secret, step, { algorithm: "SHA1", digits: 6 });
	const match = (
		code: string,
		overrides: { window?: number; nowMs?: number; lastUsedStep?: number },
	) =>
		matchTotpCode(code, {
			secret,
			algorithm: "SHA1",
			digits: 6,
			period,
			window: overrides.window ?? 1,
			nowMs: overrides.nowMs ?? nowMs,
			...(overrides.lastUsedStep !== undefined ? { lastUsedStep: overrides.lastUsedStep } : {}),
		});

	it("accepts T - window and T + window, and refuses a step beyond either edge", () => {
		for (const window of [0, 1, 2]) {
			expect(match(codeAt(T), { window }), `T, window ${window}`).toEqual({
				outcome: "matched",
				step: T,
			});
			expect(match(codeAt(T - window), { window }), `T-${window}`).toEqual({
				outcome: "matched",
				step: T - window,
			});
			expect(match(codeAt(T + window), { window }), `T+${window}`).toEqual({
				outcome: "matched",
				step: T + window,
			});
			expect(match(codeAt(T - window - 1), { window }), `T-${window + 1}`).toEqual({
				outcome: "invalid",
			});
			expect(match(codeAt(T + window + 1), { window }), `T+${window + 1}`).toEqual({
				outcome: "invalid",
			});
		}
	});

	it("moves to the next step exactly at the period boundary", () => {
		const boundary = (T + 1) * period * 1000;
		// The last millisecond of step T, and the first of T + 1, with no window.
		expect(match(codeAt(T), { window: 0, nowMs: boundary - 1 })).toEqual({
			outcome: "matched",
			step: T,
		});
		expect(match(codeAt(T + 1), { window: 0, nowMs: boundary - 1 })).toEqual({
			outcome: "invalid",
		});
		expect(match(codeAt(T + 1), { window: 0, nowMs: boundary })).toEqual({
			outcome: "matched",
			step: T + 1,
		});
		expect(match(codeAt(T), { window: 0, nowMs: boundary })).toEqual({ outcome: "invalid" });
		// With a window of one, either side of the boundary accepts both.
		for (const at of [boundary - 1, boundary]) {
			expect(match(codeAt(T), { window: 1, nowMs: at })).toEqual({ outcome: "matched", step: T });
			expect(match(codeAt(T + 1), { window: 1, nowMs: at })).toEqual({
				outcome: "matched",
				step: T + 1,
			});
		}
	});

	it("refuses a step at or before lastUsedStep as replayed: the same code again, or an older one never used", () => {
		// Reuse: T was accepted, and its code is presented again.
		expect(match(codeAt(T), { lastUsedStep: T })).toEqual({ outcome: "replayed" });
		// An older code, never used, once a newer one was accepted.
		expect(match(codeAt(T - 1), { lastUsedStep: T })).toEqual({ outcome: "replayed" });
		expect(match(codeAt(T), { lastUsedStep: T + 1 })).toEqual({ outcome: "replayed" });
		// A later step is still accepted.
		expect(match(codeAt(T + 1), { lastUsedStep: T })).toEqual({
			outcome: "matched",
			step: T + 1,
		});
		expect(match(codeAt(T), { lastUsedStep: T - 1 })).toEqual({ outcome: "matched", step: T });
	});

	it("answers invalid for a code no step in the window produces, whatever lastUsedStep says", () => {
		const wrong = String((Number(codeAt(T)) + 1) % 1_000_000).padStart(6, "0");
		expect(match(wrong, {})).toEqual({ outcome: "invalid" });
		expect(match(wrong, { lastUsedStep: T })).toEqual({ outcome: "invalid" });
		expect(match("", {})).toEqual({ outcome: "invalid" });
		expect(match(`${codeAt(T)}0`, {})).toEqual({ outcome: "invalid" });
	});

	it("never steps before the epoch", () => {
		const first = hotp(secret, 0, { algorithm: "SHA1", digits: 6 });
		expect(match(first, { window: 2, nowMs: 0 })).toEqual({ outcome: "matched", step: 0 });
	});

	it("refuses a window or a lastUsedStep it was not built for", () => {
		expect(() => match(codeAt(T), { window: -1 })).toThrow(RangeError);
		expect(() => match(codeAt(T), { window: 0.5 })).toThrow(RangeError);
		expect(() => match(codeAt(T), { lastUsedStep: 1.5 })).toThrow(RangeError);
		expect(() => match(codeAt(T), { lastUsedStep: Number.NaN })).toThrow(RangeError);
	});
});
