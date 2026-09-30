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
 * The recovery-code factor (the MFA ADR's D22, D25): contributed as
 * `mfaFactors.recovery_code` by its module while its section is on. It does
 * not count, adds `recovery` and `mfa`, is never enrolled on its own, and
 * issues a set of `count` long codes beside a first counting factor, kept as
 * keyed digests under the ring. Its verification is not built: a verification
 * is an outage (`503`), never a code accepted or refused.
 */

import { randomBytes } from "node:crypto";
import {
	createApp,
	createMemoryMfaFactorStore,
	type MfaFactorResolver,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readLongCode } from "#/codes.mjs";
import {
	createRecoveryCodeFactor,
	generateRecoveryCodes,
	RECOVERY_CODE_FACTOR_KIND,
} from "#/recovery/factor.mjs";
import { mfaRecoveryCodeFactorModule } from "#/recovery/module.mjs";
import { createMfaSealing } from "#/sealing.mjs";
import { mfaRecoveryCodeFactorConfigForTests } from "#/testing/index.mjs";
import { createTotpFactor } from "#/totp/factor.mjs";
import { boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	beginLogin,
	freezeClock,
	seedFactor,
	seedTotp,
	suiteSealing,
	thawClock,
	verify,
} from "./routesHarness.mjs";

const SHOWN = /^[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}$/;

describe("the recovery-code factor", () => {
	const factor = createRecoveryCodeFactor({ count: 10 });

	it("is recovery_code, adds recovery and mfa, does not count, is not guessed, and is enrolled by nobody", () => {
		expect(factor.kind).toBe(RECOVERY_CODE_FACTOR_KIND);
		expect(RECOVERY_CODE_FACTOR_KIND).toBe("recovery_code");
		expect(factor.amrValues).toEqual(["recovery"]);
		expect(factor.amrFor({})).toEqual(["recovery"]);
		expect(factor.addsMfa).toBe(true);
		expect(factor.counting).toBe(false);
		expect(factor.guessable).toBe(false);
		expect(factor.enrollable?.({ id: "u-alice", username: "alice" })).toBe(false);
		expect(factor.describe({})).toEqual({});
	});

	it("refuses to begin or complete an enrollment of its own: its set is issued beside a counting factor", async () => {
		const ctx = {
			subject: "u-alice",
			transactionId: "t",
			nowMs: 0,
			request: {},
			digests: suiteSealing().digestsFor(RECOVERY_CODE_FACTOR_KIND),
			user: { id: "u-alice" },
			factors: [],
		};
		await expect(factor.beginEnrollment(ctx)).rejects.toThrow(RangeError);
		await expect(factor.completeEnrollment({ ...ctx, state: {}, proof: "x" })).rejects.toThrow(
			RangeError,
		);
	});

	it("verifies nothing yet: a verification throws, which the coordinator answers as an outage", async () => {
		await expect(
			factor.verify({
				subject: "u-alice",
				transactionId: "t",
				nowMs: 0,
				request: {},
				digests: suiteSealing().digestsFor(RECOVERY_CODE_FACTOR_KIND),
				factor: {
					id: "f",
					label: undefined,
					createdAt: new Date(0),
					lastUsedAt: undefined,
					data: {},
				},
				factors: [],
				state: undefined,
				proof: "0123-4567-89AB-CDEF",
			}),
		).rejects.toThrow();
	});
});

describe("generateRecoveryCodes", () => {
	const sealing = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] });
	const digests = sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND);

	it("issues the factor's count of long codes, shown in groups, each kept as a keyed digest of the code alone", () => {
		for (const count of [1, 10, 20]) {
			const set = generateRecoveryCodes(createRecoveryCodeFactor({ count }), digests);
			expect(set?.codes, String(count)).toHaveLength(count);
			for (const code of set?.codes ?? []) expect(code).toMatch(SHOWN);
			expect(new Set(set?.codes).size, String(count)).toBe(count);
			const kept = set?.data.codes as { keyId: string; digest: string }[];
			expect(kept, String(count)).toHaveLength(count);
			set?.codes.forEach((code, index) => {
				expect(digests.matchesDigest([readLongCode(code) as string], kept[index] as never)).toBe(
					"match",
				);
			});
			const text = JSON.stringify(set?.data);
			for (const code of set?.codes ?? []) {
				expect(text).not.toContain(code);
				expect(text).not.toContain(readLongCode(code) as string);
			}
		}
	});

	it("issues nothing for a factor this package's recovery-code module did not make", () => {
		const settings = { algorithm: "SHA1", digits: 6, period: 30, window: 1, issuer: "x" } as const;
		expect(generateRecoveryCodes(createTotpFactor(settings), digests)).toBeUndefined();
		expect(
			generateRecoveryCodes({ ...createRecoveryCodeFactor({ count: 10 }) }, digests),
		).toBeUndefined();
	});
});

describe("mfaRecoveryCodeFactorModule", () => {
	let disposable: { dispose(): Promise<void> } | undefined;
	afterEach(async () => {
		await disposable?.dispose();
		disposable = undefined;
	});

	const bootWith = async (options: { readonly enabled?: boolean; readonly count?: number }) => {
		const handle = await createApp({
			modules: [mfaRecoveryCodeFactorModule],
			bootstrapComponents: {
				config: { ...makeValidAppConfig(), ...mfaRecoveryCodeFactorConfigForTests(options) },
				pathResolver: (p: string) => p,
			} as never,
		});
		disposable = handle;
		return handle.components.mfaFactorResolver as MfaFactorResolver;
	};

	it("contributes the factor while its section is on, issuing its count of codes", async () => {
		const resolver = await bootWith({ count: 12 });
		const factor = resolver.get(RECOVERY_CODE_FACTOR_KIND);
		expect(factor?.counting).toBe(false);
		const digests = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] }).digestsFor(
			RECOVERY_CODE_FACTOR_KIND,
		);
		expect(factor && generateRecoveryCodes(factor, digests)?.codes).toHaveLength(12);
	});

	it("contributes none while its section is off", async () => {
		const resolver = await bootWith({ enabled: false });
		expect(resolver.get(RECOVERY_CODE_FACTOR_KIND)).toBeUndefined();
		expect([...resolver.entries()]).toEqual([]);
	});
});

describe("a recovery code at a login", () => {
	beforeEach(() => freezeClock());
	afterEach(async () => {
		await disposeAll();
		thawClock();
	});

	it("is answered 503 once — mfa_factor_unreadable, the verification — and no session: verification is not built", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const record = await seedFactor(factorStore, RECOVERY_CODE_FACTOR_KIND, { codes: [] });
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, "0123-4567-89AB-CDEF");

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			kind: RECOVERY_CODE_FACTOR_KIND,
			state: "verification",
		});
		expect(create).not.toHaveBeenCalled();
	});
});
