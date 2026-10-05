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
 * The first-binding mark as the MFA package notes and reads it (the MFA
 * ADR's D12): how long it stands, how a store's answer is read, and which
 * authentication it distrusts.
 */

import { DEFAULT_CLOCK_SKEW_MS, MFA_CLOCK_SKEW_ALLOWANCE_MS } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { MFA_RECENT_WINDOW_SECONDS } from "#/config.mjs";
import {
	createFirstBindingMark,
	firstBindingMarkLifetimeMs,
	readFirstBindingMark,
} from "#/firstBindingMark.mjs";
import { MFA_TRANSACTION_TTL_SECONDS } from "#/transactions.mjs";

const NOW = 1_800_000_010_000;
const LEASE_MS = 80_000;
/** The mark at the default settings: a factor-set lease of 16 × the 5000 ms Store timeout. */
const MARK = createFirstBindingMark({
	manageMaxAgeSeconds: 300,
	transactionTtlSeconds: 600,
	leaseMs: LEASE_MS,
});

describe("the mark's lifetime", () => {
	it("is max(mfa.manage.maxAgeSeconds, 2 × mfa.transactionTtlSeconds), twice the clock skew and one factor-set lease, in whole milliseconds", () => {
		for (const [manageMaxAgeSeconds, transactionTtlSeconds, expected] of [
			[300, 600, 1_200_000],
			[3600, 60, 3_600_000],
			[60, 1800, 3_600_000],
			[3600, 1800, 3_600_000],
		] as const) {
			const lifetime = firstBindingMarkLifetimeMs({
				manageMaxAgeSeconds,
				transactionTtlSeconds,
				leaseMs: 80_000,
			});
			expect(lifetime).toBe(expected + 2 * DEFAULT_CLOCK_SKEW_MS + 80_000);
			expect(Number.isSafeInteger(lifetime)).toBe(true);
		}
	});

	it("outlasts the skew and a lease by at least a minute at the shortest windows and the longest lease: a regeneration can rely on it", () => {
		const lifetime = firstBindingMarkLifetimeMs({
			manageMaxAgeSeconds: MFA_RECENT_WINDOW_SECONDS.min,
			transactionTtlSeconds: MFA_TRANSACTION_TTL_SECONDS.min,
			leaseMs: 600_000,
		});
		expect(lifetime - DEFAULT_CLOCK_SKEW_MS - 600_000).toBeGreaterThanOrEqual(60_000);
	});

	it("answers the lifetime it was built with, and a read covers a mark noted since for that lifetime less the skew and the lease", () => {
		const lifetime = firstBindingMarkLifetimeMs({
			manageMaxAgeSeconds: 300,
			transactionTtlSeconds: 600,
			leaseMs: LEASE_MS,
		});
		expect(MARK.lifetimeMs).toBe(lifetime);
		expect(MARK.readCoversMs).toBe(lifetime - DEFAULT_CLOCK_SKEW_MS - LEASE_MS);
	});

	it("stays within a day, the most a store keeps a mark, at the longest mfa.manage.maxAgeSeconds and mfa.transactionTtlSeconds admit", () => {
		expect(
			firstBindingMarkLifetimeMs({
				manageMaxAgeSeconds: MFA_RECENT_WINDOW_SECONDS.max,
				transactionTtlSeconds: MFA_TRANSACTION_TTL_SECONDS.max,
				leaseMs: 600_000,
			}),
		).toBeLessThanOrEqual(MFA_CLOCK_SKEW_ALLOWANCE_MS);
	});
});

describe("a store's answer", () => {
	it("reads none as none, and a time up to the clock skew ahead as that time", () => {
		expect(readFirstBindingMark(null, NOW)).toBeNull();
		expect(readFirstBindingMark(NOW - 60_000, NOW)).toBe(NOW - 60_000);
		expect(readFirstBindingMark(NOW + DEFAULT_CLOCK_SKEW_MS, NOW)).toBe(
			NOW + DEFAULT_CLOCK_SKEW_MS,
		);
	});

	it("throws for anything else — never read as none", () => {
		for (const answer of [
			undefined,
			"now",
			Number.NaN,
			NOW - 0.5,
			-1,
			NOW + DEFAULT_CLOCK_SKEW_MS + 1,
			{ atMs: NOW },
		]) {
			expect(() => readFirstBindingMark(answer, NOW), String(answer)).toThrow(TypeError);
		}
	});
});

describe("which authentication the mark distrusts", () => {
	it("one at or before the mark, the clock skew and one factor-set lease — a sign-in made while the marked write may still have been landing; not one a millisecond later, nor any without a mark", () => {
		const at = NOW - 60_000;
		expect(MARK.distrusts(at - 1, at)).toBe(true);
		expect(MARK.distrusts(at + DEFAULT_CLOCK_SKEW_MS + 1_000, at)).toBe(true);
		expect(MARK.distrusts(at + DEFAULT_CLOCK_SKEW_MS + LEASE_MS, at)).toBe(true);
		expect(MARK.distrusts(at + DEFAULT_CLOCK_SKEW_MS + LEASE_MS + 1, at)).toBe(false);
		expect(MARK.distrusts(at - 1, null)).toBe(false);
	});

	it("one whose time cannot be read, whenever a mark stands", () => {
		for (const authTimeMs of [Number.NaN, undefined]) {
			expect(MARK.distrusts(authTimeMs, NOW)).toBe(true);
		}
	});

	it("until the mark, the skew and the lease have passed: how long a fresh sign-in waits, never less than none", () => {
		expect(MARK.retryAfterMs(NOW, NOW)).toBe(DEFAULT_CLOCK_SKEW_MS + LEASE_MS + 1);
		expect(MARK.retryAfterMs(NOW, NOW + DEFAULT_CLOCK_SKEW_MS + LEASE_MS + 1)).toBe(0);
		expect(MARK.retryAfterMs(NOW, NOW + 3_600_000)).toBe(0);
	});
});
