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
 * A revoked family's record is kept until the last token of the family could
 * still be accepted, whatever the family's own lifetime.
 *
 * `isFamilyRevoked` answers "no" for a family whose record is gone, and the
 * record expired with the family — its refresh-token lifetime, set once at
 * creation — because revocation kept that expiry. An access token minted late
 * in the family's life outlives it, and the verifier accepts a token for its
 * clock tolerance past `exp` besides. So revocation extends the record to
 * the later of the family's own expiry and now plus the longest access-token
 * lifetime the configuration allows, plus that tolerance; and a family whose
 * record had already run out is recorded as revoked anyway.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	DEFAULT_CLOCK_SKEW_MS,
	DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
	REVOCATION_RETENTION_ALLOWANCE_MS,
} from "#/jwt/verify.mjs";
import { createMemoryRefreshTokenFamilyStore } from "#/refresh-token-family/adapters/memory.mjs";
import {
	defaultRefreshTokenFamilyRevocationModule,
	defaultRefreshTokenFamilyRotationModule,
} from "#/refresh-token-family/module.mjs";
import {
	resolveFamilyAccessTokenHorizonMs,
	revokedFamilyExpiresAtMs,
} from "#/refresh-token-family/retention.mjs";
import { createRefreshTokenFamilyRevocation } from "#/refresh-token-family/revocation.mjs";
import { createRefreshTokenFamilyRotation } from "#/refresh-token-family/rotation.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

describe("the retention rule", () => {
	it("is the access-token maximum, from the configuration — not the default", () => {
		const config = makeValidCoreConfig();
		expect(
			resolveFamilyAccessTokenHorizonMs({
				...config,
				oauth: { ...config.oauth, accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7200 } },
			}),
		).toBe(7_200_000);
		// The shipped shape: the deprecated key read as default and max.
		expect(resolveFamilyAccessTokenHorizonMs(config)).toBe(3_600_000);
	});

	it("refuses a configuration with no access-token lifetime to size it from", () => {
		expect(() => resolveFamilyAccessTokenHorizonMs({ oauth: {} })).toThrow(/accessToken/);
	});

	it("covers the verifier's clock tolerance, the replica allowance and a second of rounding", () => {
		expect(REVOCATION_RETENTION_ALLOWANCE_MS).toBe(
			DEFAULT_CLOCK_SKEW_MS + DEFAULT_SUBJECT_REVOCATION_SKEW_MS + 1_000,
		);
	});

	it("keeps the later of the family's own expiry and the last access token's", () => {
		const now = 1_000_000_000_000;
		// Early in the family's life its own expiry is the later one.
		expect(revokedFamilyExpiresAtMs({ expiresAtMs: now + 20 * HOUR }, now, HOUR)).toBe(
			now + 20 * HOUR + REVOCATION_RETENTION_ALLOWANCE_MS,
		);
		// Late in it, an access token minted now outlives the family.
		expect(revokedFamilyExpiresAtMs({ expiresAtMs: now + 10 * MINUTE }, now, HOUR)).toBe(
			now + HOUR + REVOCATION_RETENTION_ALLOWANCE_MS,
		);
	});

	it("is a whole millisecond, rounded up — Redis writes it as PX and reads it back as an integer", () => {
		const now = 1_000_000_000_000;
		expect(revokedFamilyExpiresAtMs({ expiresAtMs: now }, now, HOUR + 0.25)).toBe(
			now + HOUR + 1 + REVOCATION_RETENTION_ALLOWANCE_MS,
		);
		expect(revokedFamilyExpiresAtMs({ expiresAtMs: now + 2 * HOUR + 0.5 }, now, HOUR)).toBe(
			now + 2 * HOUR + 1 + REVOCATION_RETENTION_ALLOWANCE_MS,
		);
	});
});

describe("revokeFamily keeps the record as long as the rule says", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	const seed = async (familyLifetimeMs: number) => {
		const store = createMemoryRefreshTokenFamilyStore();
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: store,
			accessTokenHorizonMs: HOUR,
		});
		await store.registerFamily({
			familyId: "fam-1",
			activeJti: "jti-1",
			revoked: false,
			expiresAtMs: Date.now() + familyLifetimeMs,
		});
		return { store, revocation };
	};

	it("still answers revoked after the family's own expiry, until the last access token's", async () => {
		const { revocation } = await seed(10 * MINUTE);
		await revocation.revokeFamily("fam-1");

		vi.setSystemTime(Date.now() + 11 * MINUTE);
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(true);

		// An access token minted just before the revocation is accepted until
		// an hour later plus the tolerance — and the record lasts that long.
		vi.setSystemTime(Date.now() + 49 * MINUTE + REVOCATION_RETENTION_ALLOWANCE_MS - 1_000);
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(true);
	});

	it("keeps a long-lived family's own expiry when that is the later one", async () => {
		const { store, revocation } = await seed(20 * HOUR);
		await revocation.revokeFamily("fam-1");
		expect((await store.findFamily("fam-1"))?.expiresAtMs).toBe(
			Date.now() + 20 * HOUR + REVOCATION_RETENTION_ALLOWANCE_MS,
		);
	});

	it("records the revocation of a family whose record has already run out", async () => {
		const { store, revocation } = await seed(10 * MINUTE);
		vi.setSystemTime(Date.now() + 11 * MINUTE);
		expect(await store.findFamily("fam-1")).toBeNull();

		await revocation.revokeFamily("fam-1");
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(true);
		expect(await store.findFamily("fam-1")).toMatchObject({
			familyId: "fam-1",
			revoked: true,
			expiresAtMs: Date.now() + HOUR + REVOCATION_RETENTION_ALLOWANCE_MS,
		});
	});

	it("leaves an already-revoked family as it is", async () => {
		const { store, revocation } = await seed(10 * MINUTE);
		await revocation.revokeFamily("fam-1");
		const first = await store.findFamily("fam-1");
		vi.setSystemTime(Date.now() + MINUTE);
		await revocation.revokeFamily("fam-1");
		expect(await store.findFamily("fam-1")).toEqual(first);
	});

	it("refuses to be built without a horizon, or with one that is not a lifetime", () => {
		const store = createMemoryRefreshTokenFamilyStore();
		for (const accessTokenHorizonMs of [undefined, 0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() =>
				createRefreshTokenFamilyRevocation({
					refreshTokenFamilyStore: store,
					accessTokenHorizonMs: accessTokenHorizonMs as number,
				}),
			).toThrow(/accessTokenHorizonMs/);
			expect(() =>
				createRefreshTokenFamilyRotation({
					refreshTokenFamilyStore: store,
					accessTokenHorizonMs: accessTokenHorizonMs as number,
				}),
			).toThrow(/accessTokenHorizonMs/);
		}
	});
});

describe("a replay revokes the family for as long as the rule says", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("keeps the record revoked past the family's own expiry", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const rotation = createRefreshTokenFamilyRotation({
			refreshTokenFamilyStore: store,
			accessTokenHorizonMs: HOUR,
		});
		const revocation = createRefreshTokenFamilyRevocation({
			refreshTokenFamilyStore: store,
			accessTokenHorizonMs: HOUR,
		});
		const familyEnds = Date.now() + 10 * MINUTE;
		await rotation.register("jti-1", "fam-1", familyEnds);
		await rotation.rotate("jti-1", "jti-2", "fam-1", familyEnds);
		expect(await rotation.rotate("jti-1", "jti-evil", "fam-1", familyEnds)).toEqual({
			outcome: "replayed",
			familyRevoked: true,
		});

		vi.setSystemTime(Date.now() + 11 * MINUTE);
		expect(await revocation.isFamilyRevoked("fam-1")).toBe(true);
	});
});

describe("the default modules size the horizon from the configuration", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("require config beside the store", () => {
		expect(new Set(defaultRefreshTokenFamilyRevocationModule.requires ?? [])).toEqual(
			new Set(["refreshTokenFamilyStore", "config"]),
		);
		expect(new Set(defaultRefreshTokenFamilyRotationModule.requires ?? [])).toEqual(
			new Set(["refreshTokenFamilyStore", "config"]),
		);
	});

	it("keep a revoked record for the configured access-token maximum", async () => {
		const store = createMemoryRefreshTokenFamilyStore();
		const base = makeValidCoreConfig();
		const config = {
			...base,
			oauth: { ...base.oauth, accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7200 } },
		};
		const revocation =
			await defaultRefreshTokenFamilyRevocationModule.provides?.refreshTokenFamilyRevocation?.({
				refreshTokenFamilyStore: store,
				config,
			} as never);
		if (!revocation) throw new Error("the module provides no refreshTokenFamilyRevocation");
		await store.registerFamily({
			familyId: "fam-1",
			activeJti: "jti-1",
			revoked: false,
			expiresAtMs: Date.now() + 10 * MINUTE,
		});
		await revocation.revokeFamily("fam-1");
		expect((await store.findFamily("fam-1"))?.expiresAtMs).toBe(
			Date.now() + 2 * HOUR + REVOCATION_RETENTION_ALLOWANCE_MS,
		);
	});
});
