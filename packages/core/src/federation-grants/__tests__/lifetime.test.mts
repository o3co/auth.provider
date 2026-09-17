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

import { describe, expect, it } from "vitest";
import {
	FEDERATION_GRANT_LIFETIME_CEILING_MS,
	federationGrantEffectiveExpiry,
	federationGrantExpiresAt,
	federationGrantExpiryState,
	resolveFederationGrantLifetimeMs,
	withinFederationGrantLifetimeCeiling,
} from "#/federation-grants/lifetime.mjs";

const DAY = 86_400_000;
const CONSENT = new Date("2026-09-18T00:00:00.000Z");
const INVALID = new Date(Number.NaN);
const at = (ms: number) => new Date(CONSENT.getTime() + ms);

/** A grant as the expiry rules see it: when it was consented, and until when. */
const grant = (lifetimeMs: number) => ({ consent: { at: CONSENT }, expiresAt: at(lifetimeMs) });

describe("federation grant lifetime (#593, D3)", () => {
	describe("FEDERATION_GRANT_LIFETIME_CEILING_MS", () => {
		it("is one year, the ceiling the config schema puts on every duration", () => {
			expect(FEDERATION_GRANT_LIFETIME_CEILING_MS).toBe(365 * DAY);
		});
	});

	describe("resolveFederationGrantLifetimeMs", () => {
		const limits = { defaultMs: 30 * DAY, maxMs: 90 * DAY };

		it("uses the default when the intent asks for nothing", () => {
			expect(resolveFederationGrantLifetimeMs(limits)).toBe(30 * DAY);
		});

		it("honours a request within the maximum", () => {
			expect(resolveFederationGrantLifetimeMs({ ...limits, requestedMs: 45 * DAY })).toBe(45 * DAY);
		});

		it("clamps a request above the maximum, and does not reject it", () => {
			expect(resolveFederationGrantLifetimeMs({ ...limits, requestedMs: 200 * DAY })).toBe(
				90 * DAY,
			);
		});

		it("clamps to the ceiling when a hand-built config carries a maximum above it", () => {
			// A schema caps the maximum at one year, and a hand-built config
			// bypasses a schema (#448). The ceiling is enforced here too.
			const loose = { defaultMs: 30 * DAY, maxMs: 800 * DAY };
			expect(resolveFederationGrantLifetimeMs({ ...loose, requestedMs: 700 * DAY })).toBe(
				FEDERATION_GRANT_LIFETIME_CEILING_MS,
			);
		});

		it("clamps the default too: a default above the maximum is not a way round it", () => {
			expect(resolveFederationGrantLifetimeMs({ defaultMs: 120 * DAY, maxMs: 90 * DAY })).toBe(
				90 * DAY,
			);
		});

		it("refuses a lifetime that is not a positive finite number", () => {
			for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
				expect(() => resolveFederationGrantLifetimeMs({ ...limits, requestedMs: bad })).toThrow(
					RangeError,
				);
			}
			expect(() => resolveFederationGrantLifetimeMs({ defaultMs: 0, maxMs: 90 * DAY })).toThrow(
				RangeError,
			);
			expect(() =>
				resolveFederationGrantLifetimeMs({ defaultMs: 30 * DAY, maxMs: Number.NaN }),
			).toThrow(RangeError);
		});
	});

	describe("federationGrantExpiresAt", () => {
		it("counts from consent, not from the callback that follows it", () => {
			expect(federationGrantExpiresAt(CONSENT, 30 * DAY)).toEqual(at(30 * DAY));
		});
	});

	describe("withinFederationGrantLifetimeCeiling", () => {
		it("accepts a lifetime up to the ceiling and refuses one beyond it", () => {
			const ceiling = FEDERATION_GRANT_LIFETIME_CEILING_MS;
			expect(withinFederationGrantLifetimeCeiling(CONSENT, at(ceiling))).toBe(true);
			expect(withinFederationGrantLifetimeCeiling(CONSENT, at(ceiling + 1))).toBe(false);
		});

		it("refuses an expiry that does not come after the consent", () => {
			expect(withinFederationGrantLifetimeCeiling(CONSENT, CONSENT)).toBe(false);
			expect(withinFederationGrantLifetimeCeiling(CONSENT, at(-1))).toBe(false);
		});

		it("refuses dates that are not dates", () => {
			expect(withinFederationGrantLifetimeCeiling(INVALID, at(DAY))).toBe(false);
			expect(withinFederationGrantLifetimeCeiling(CONSENT, INVALID)).toBe(false);
		});
	});

	describe("federationGrantEffectiveExpiry", () => {
		it("is the consented expiry while the operator's maximum allows it", () => {
			expect(federationGrantEffectiveExpiry(grant(30 * DAY), 90 * DAY)).toEqual(at(30 * DAY));
		});

		it("is shortened by a maximum lowered after the consent", () => {
			expect(federationGrantEffectiveExpiry(grant(90 * DAY), 30 * DAY)).toEqual(at(30 * DAY));
		});

		it("is never lengthened by a maximum raised after the consent", () => {
			expect(federationGrantEffectiveExpiry(grant(30 * DAY), 300 * DAY)).toEqual(at(30 * DAY));
		});
	});

	describe("federationGrantExpiryState", () => {
		it("is live before either bound", () => {
			expect(federationGrantExpiryState(grant(90 * DAY), at(10 * DAY), 90 * DAY)).toBe("live");
		});

		it("names the consented lifetime from the instant the stored expiry is reached — that one is terminal", () => {
			expect(federationGrantExpiryState(grant(30 * DAY), at(30 * DAY - 1), 90 * DAY)).toBe("live");
			expect(federationGrantExpiryState(grant(30 * DAY), at(30 * DAY), 90 * DAY)).toBe(
				"consented_lifetime",
			);
			expect(federationGrantExpiryState(grant(30 * DAY), at(31 * DAY), 90 * DAY)).toBe(
				"consented_lifetime",
			);
		});

		it("names the operator's maximum from the instant it is reached — raising it lifts the expiry", () => {
			expect(federationGrantExpiryState(grant(90 * DAY), at(30 * DAY - 1), 30 * DAY)).toBe("live");
			expect(federationGrantExpiryState(grant(90 * DAY), at(30 * DAY), 30 * DAY)).toBe(
				"operator_maximum",
			);
			expect(federationGrantExpiryState(grant(90 * DAY), at(40 * DAY), 30 * DAY)).toBe(
				"operator_maximum",
			);
			expect(federationGrantExpiryState(grant(90 * DAY), at(40 * DAY), 60 * DAY)).toBe("live");
		});

		it("prefers the terminal reason when both bounds have passed", () => {
			expect(federationGrantExpiryState(grant(30 * DAY), at(40 * DAY), 20 * DAY)).toBe(
				"consented_lifetime",
			);
		});

		it("never reads as live on a value it cannot compare", () => {
			// Every comparison with NaN is false, so a rule written as "has it
			// passed?" answers no, and a corrupt record would live for ever.
			expect(
				federationGrantExpiryState(
					{ consent: { at: CONSENT }, expiresAt: INVALID },
					at(DAY),
					90 * DAY,
				),
			).toBe("consented_lifetime");
			expect(federationGrantExpiryState(grant(90 * DAY), INVALID, 90 * DAY)).toBe(
				"consented_lifetime",
			);
			expect(
				federationGrantExpiryState(
					{ consent: { at: INVALID }, expiresAt: at(90 * DAY) },
					at(DAY),
					90 * DAY,
				),
			).toBe("operator_maximum");
			expect(federationGrantExpiryState(grant(90 * DAY), at(DAY), Number.NaN)).toBe(
				"operator_maximum",
			);
		});
	});
});
