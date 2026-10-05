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
 * `federation-grants {}` as an operator writes it, turned into the limits the
 * retrieval takes (ADR 2026-09-17-federation-grants-offline-delegation, D3,
 * D10 and D12). The conversion goes wrong silently: seconds forwarded as
 * milliseconds, or a default substituted for an explicitly invalid value,
 * which turns a typo into a deployment nobody chose. So it is a named
 * function, tested directly.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	FEDERATION_GRANT_SETTING_DEFAULTS,
	resolveFederationGrantAcquisitionLimits,
	resolveFederationGrantKeepPolicy,
	resolveFederationGrantRetrievalLimits,
} from "#/federation-grants/settings.mjs";

/** The federation-grants package's `reference.conf`, which ships the section's defaults. */
const referenceConf = readFileSync(
	fileURLToPath(new URL("../../../../federation-grants/config/reference.conf", import.meta.url)),
	"utf8",
);

/** The `federation-grants` section of that file, as `key = number` pairs. */
function shippedDefaults(): Record<string, number> {
	const block = /\nfederation-grants \{\n([\s\S]*?)\n\}/.exec(referenceConf);
	const found: Record<string, number> = {};
	for (const line of (block?.[1] ?? "").split("\n")) {
		const pair = /^\s{2}([A-Za-z]+) = (\d+)$/.exec(line);
		if (pair?.[1] !== undefined) found[pair[1]] = Number(pair[2]);
	}
	return found;
}

describe("FEDERATION_GRANT_SETTING_DEFAULTS", () => {
	it("is the block reference.conf ships, value for value", () => {
		// Two copies of a default is two things to change, and the one that is
		// forgotten is the one a hand-built configuration gets. The copies are
		// held together here rather than by a comment asking someone to.
		const shipped = shippedDefaults();
		expect(Object.keys(shipped).length).toBeGreaterThan(8);
		for (const [key, value] of Object.entries(shipped)) {
			expect(
				(FEDERATION_GRANT_SETTING_DEFAULTS as Record<string, number>)[key],
				`reference.conf federation-grants.${key}`,
			).toBe(value);
		}
	});
});

describe("resolveFederationGrantKeepPolicy", () => {
	const resolve = (written: unknown) =>
		resolveFederationGrantKeepPolicy({ allowKeepOnSubjectRevocation: written });

	it("is off when an operator wrote nothing", () => {
		// Including the deployments that predate the key: what a subject-wide
		// revocation did before this existed is what it keeps doing.
		expect(resolveFederationGrantKeepPolicy({})).toBe(false);
		expect(resolveFederationGrantKeepPolicy(undefined)).toBe(false);
		expect(resolve(undefined)).toBe(false);
	});

	it("reads the spellings HOCON substitutes an environment variable as", () => {
		for (const written of [true, "true", "TRUE", " 1 "]) {
			expect(resolve(written), JSON.stringify(written)).toBe(true);
		}
		// An empty value is an unset `${?VAR}` chain, and it reads as false.
		for (const written of [false, "false", "0", ""]) {
			expect(resolve(written), JSON.stringify(written)).toBe(false);
		}
	});

	it("refuses a value it would have to guess at, rather than reading it as on", () => {
		// The direction matters: an allowance nobody can read must not become
		// one an operator never gave.
		for (const written of ["yes", "on", 1, null, [], {}]) {
			expect(() => resolve(written), JSON.stringify(written)).toThrow(
				/allowKeepOnSubjectRevocation/,
			);
		}
	});
});

describe("resolveFederationGrantRetrievalLimits", () => {
	it("converts every seconds-based setting into the milliseconds the retrieval takes", () => {
		const limits = resolveFederationGrantRetrievalLimits({
			maxExpiresIn: 86_400,
			refreshBuffer: 45,
			ineligibleRetryAfter: 600,
			refreshFailureBackoff: 15,
		});
		expect(limits.maxExpiresInMs).toBe(86_400_000);
		expect(limits.refreshBufferMs).toBe(45_000);
		expect(limits.ineligibleRetryAfterMs).toBe(600_000);
		expect(limits.refreshFailureBackoffMs).toBe(15_000);
	});

	it("passes the millisecond settings through as they are written", () => {
		const limits = resolveFederationGrantRetrievalLimits({
			upstreamTimeoutMs: 8_000,
			upstreamHardTimeoutMs: 20_000,
			refreshLockTtlMs: 25_000,
			lockWaitMs: 4_000,
			persistRetryBudgetMs: 2_000,
		});
		expect(limits.upstreamTimeoutMs).toBe(8_000);
		expect(limits.upstreamHardTimeoutMs).toBe(20_000);
		expect(limits.refreshLockTtlMs).toBe(25_000);
		expect(limits.lockWaitMs).toBe(4_000);
		expect(limits.persistRetryBudgetMs).toBe(2_000);
	});

	it("fills an absent knob from the shipped default", () => {
		const limits = resolveFederationGrantRetrievalLimits({});
		expect(limits.refreshBufferMs).toBe(FEDERATION_GRANT_SETTING_DEFAULTS.refreshBuffer * 1000);
		expect(limits.upstreamHardTimeoutMs).toBe(
			FEDERATION_GRANT_SETTING_DEFAULTS.upstreamHardTimeoutMs,
		);
	});

	it("takes the subject-revocation allowance rather than inventing a second one", () => {
		// The revocation backstop (ADR
		// 2026-09-17-federation-grants-offline-delegation, D13) is compared
		// against the watermark `verifyJwt` reads, so a federation-grant-specific
		// skew would be a second allowance for one comparison, and the
		// boundary's retention would have to cover whichever is larger.
		const limits = resolveFederationGrantRetrievalLimits({});
		expect(limits.revocationSkewMs).toBe(1_000);
	});

	it("refuses an explicitly invalid value rather than defaulting over it", () => {
		// A default substituted here is a typo that boots.
		for (const section of [
			{ refreshBuffer: -1 },
			{ upstreamTimeoutMs: 0 },
			{ maxExpiresIn: Number.NaN },
			{ lockWaitMs: "soon" },
		]) {
			expect(
				() => resolveFederationGrantRetrievalLimits(section),
				JSON.stringify(section),
			).toThrow();
		}
	});

	it("refuses a fraction of a second, and says which key it was", async () => {
		// The relationships between the timers are checked downstream, and they
		// accept 1.5 seconds happily. What this refuses is the unit: every
		// unsuffixed setting is whole seconds and every `*Ms` one is whole
		// milliseconds, and an operator who wrote otherwise meant something
		// else. The message names the key because a deployment has ten of them.
		expect(() => resolveFederationGrantRetrievalLimits({ refreshBuffer: 1.5 })).toThrow(
			/refreshBuffer.*whole number of seconds/,
		);
		expect(() => resolveFederationGrantRetrievalLimits({ lockWaitMs: 2.5 })).toThrow(
			/lockWaitMs.*whole number of milliseconds/,
		);
	});

	it("refuses a value that is not a number, rather than coercing it into one", async () => {
		// `Number(x)` is a wide door: `null` and `[]` are 0, `true` is 1,
		// `[45]` is 45, `"0x10"` is 16, a `Date` is its epoch milliseconds. Two
		// of those arrive through the shipped schema too
		// (`z.coerce.number().int().nonnegative()` takes `null` as 0), and
		// `refreshBuffer = 0` hands out tokens with milliseconds of life left
		// instead of refreshing them.
		for (const refreshBuffer of [null, true, false, [], [45], "0x10", "1e3", " ", new Date(1000)]) {
			expect(
				() => resolveFederationGrantRetrievalLimits({ refreshBuffer }),
				JSON.stringify(refreshBuffer),
			).toThrow(/refreshBuffer/);
		}
	});

	it("takes the decimal string an environment variable arrives as", async () => {
		// The other half of the same rule: HOCON substitutes `${?VAR}` as a
		// string, always, so a plain decimal one is what an operator wrote.
		expect(resolveFederationGrantRetrievalLimits({ refreshBuffer: "45" }).refreshBufferMs).toBe(
			45_000,
		);
	});

	it("refuses an allowance so large that nothing is ever fresh", async () => {
		// `1e21` is an integer as far as `Number.isInteger` is concerned, and
		// `refreshBufferMs` is an allowance rather than a timer, so the
		// downstream check only asks for finite and non-negative. A buffer
		// past the ceiling makes every token look stale for ever.
		expect(() => resolveFederationGrantRetrievalLimits({ refreshBuffer: 1e21 })).toThrow(
			/refreshBuffer/,
		);
		expect(() => resolveFederationGrantRetrievalLimits({ lockWaitMs: 1e21 })).toThrow(/lockWaitMs/);
	});

	it("refuses a soft deadline past the hard one, and a lock that cannot outlive a refresh", () => {
		expect(() =>
			resolveFederationGrantRetrievalLimits({
				upstreamTimeoutMs: 30_000,
				upstreamHardTimeoutMs: 25_000,
			}),
		).toThrow();
		expect(() => resolveFederationGrantRetrievalLimits({ refreshLockTtlMs: 26_000 })).toThrow();
	});

	it("refuses a grant lifetime past the one-year ceiling the code enforces", () => {
		// `assertFederationGrantRetrievalLimits` does not check this one — it
		// is a lifetime, not a timer — so the resolver has to.
		expect(() => resolveFederationGrantRetrievalLimits({ maxExpiresIn: 31_536_001 })).toThrow(
			/maxExpiresIn/,
		);
	});

	it("reads the rotation budget: 24 rotations a window of an hour, unless written otherwise", () => {
		expect(resolveFederationGrantRetrievalLimits({})).toMatchObject({
			rotationBudget: 24,
			rotationWindowMs: 3_600_000,
		});
		expect(
			resolveFederationGrantRetrievalLimits({ rotationBudget: 6, rotationWindow: "600" }),
		).toMatchObject({ rotationBudget: 6, rotationWindowMs: 600_000 });
	});

	it("refuses a rotation budget that admits nothing, or a window that never closes or never opens", () => {
		// A budget of 0 would still let a store admit a window's first take; a
		// window of 0 reopens on every take.
		expect(() => resolveFederationGrantRetrievalLimits({ rotationBudget: 0 })).toThrow(
			/rotationBudget/,
		);
		expect(() => resolveFederationGrantRetrievalLimits({ rotationBudget: 1.5 })).toThrow(
			/rotationBudget.*whole number of rotations/,
		);
		expect(() => resolveFederationGrantRetrievalLimits({ rotationWindow: 0 })).toThrow(
			/rotationWindow/,
		);
		expect(() => resolveFederationGrantRetrievalLimits({ rotationWindow: 0.5 })).toThrow(
			/rotationWindow.*whole number of seconds/,
		);
	});

	it("refuses a backoff longer than the interval that is meant to bound it", () => {
		expect(() =>
			resolveFederationGrantRetrievalLimits({
				refreshFailureBackoff: 600,
				ineligibleRetryAfter: 300,
			}),
		).toThrow();
	});
});

describe("resolveFederationGrantAcquisitionLimits", () => {
	it("reads defaultExpiresIn, which nothing read before, in the milliseconds lodging takes", () => {
		expect(resolveFederationGrantAcquisitionLimits({})).toEqual({
			defaultLifetimeMs: 2_592_000_000,
			maxLifetimeMs: 2_592_000_000,
		});
		expect(
			resolveFederationGrantAcquisitionLimits({ defaultExpiresIn: 86_400, maxExpiresIn: "604800" }),
		).toEqual({ defaultLifetimeMs: 86_400_000, maxLifetimeMs: 604_800_000 });
	});

	it("refuses a default the maximum would silently cut down", () => {
		expect(() =>
			resolveFederationGrantAcquisitionLimits({
				defaultExpiresIn: 7_776_000,
				maxExpiresIn: 2_592_000,
			}),
		).toThrow(/defaultExpiresIn .* must not exceed/);
	});

	it("refuses a default of nothing, a maximum of nothing, and a maximum past the ceiling", () => {
		expect(() => resolveFederationGrantAcquisitionLimits({ defaultExpiresIn: 0 })).toThrow(
			/positive/,
		);
		// Zero passes the seconds reader, which takes any whole number from 0;
		// a grant that may live no time at all is the maximum's own refusal.
		expect(() => resolveFederationGrantAcquisitionLimits({ maxExpiresIn: 0 })).toThrow(
			/maxExpiresIn must be a positive number of seconds/,
		);
		expect(() => resolveFederationGrantAcquisitionLimits({ maxExpiresIn: 31_536_001 })).toThrow(
			/one year|no greater than/,
		);
	});
});
