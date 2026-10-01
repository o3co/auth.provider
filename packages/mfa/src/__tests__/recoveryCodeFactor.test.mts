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
 * keyed digests under the ring. A verification compares the code with every
 * digest of the set and answers the set without the one it matched; a
 * digest whose key left the ring is an outage (`503`), never a code refused.
 */

import { randomBytes } from "node:crypto";
import {
	createApp,
	createMemoryMfaFactorStore,
	type MfaFactor,
	type MfaFactorResolver,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readLongCode } from "#/codes.mjs";
import {
	createRecoveryCodeFactor,
	generateRecoveryCodes,
	RECOVERY_CODE_FACTOR_KIND,
	recoveryCodesLeft,
} from "#/recovery/factor.mjs";
import { issueRecoveryCodes } from "#/recovery/issue.mjs";
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
});

describe("the recovery-code factor's verification", () => {
	const factor = createRecoveryCodeFactor({ count: 10 });
	const sealing = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] });
	const digests = sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND);
	const CODE = "0123456789ABCDEF";
	const OTHER = "ZZZZYYYYXXXXWWWW";
	const setOf = (...codes: string[]) => ({ codes: codes.map((code) => digests.digest([code])) });
	const verifying = (
		proof: unknown,
		data: Record<string, unknown> = setOf(CODE, OTHER),
		using = digests,
	) =>
		factor.verify({
			subject: "u-alice",
			transactionId: "t",
			nowMs: 0,
			request: {},
			digests: using,
			factor: {
				id: "f-set",
				label: undefined,
				createdAt: new Date(0),
				lastUsedAt: undefined,
				data,
			},
			factors: [],
			state: undefined,
			proof,
		});

	it.each([
		["as shown", "0123-4567-89AB-CDEF"],
		["in lower case", "0123-4567-89ab-cdef"],
		["without hyphens", "0123456789ABCDEF"],
		["with O, I and L for the digits they stand for", "O123-4567-89AB-CDEF".replace("1", "I")],
		["with L for one", "0L23-4567-89AB-CDEF"],
		["with whitespace around it", "  0123-4567-89AB-CDEF\n"],
	])("accepts a right code %s, answering the set without it", async (_, proof) => {
		expect(await verifying(proof)).toEqual({
			ok: true,
			factorId: "f-set",
			next: { codes: [digests.digest([OTHER])] },
		});
	});

	it("refuses a wrong code as invalid, and anything that is no code as malformed", async () => {
		expect(await verifying("ZZZZ-ZZZZ-ZZZZ-ZZZZ")).toEqual({ ok: false, reason: "invalid" });
		for (const proof of [
			"123456",
			"",
			42,
			null,
			undefined,
			{ code: CODE },
			"0123-4567-89AB-CDEU",
		]) {
			expect(await verifying(proof), JSON.stringify(proof)).toEqual({
				ok: false,
				reason: "malformed",
			});
		}
	});

	it("refuses a code already spent: the set it answered no longer holds it", async () => {
		const first = await verifying(CODE);
		const next = first.ok ? (first.next as Record<string, unknown>) : {};

		expect(await verifying(CODE, next)).toEqual({ ok: false, reason: "invalid" });
	});

	it("answers an empty set for the last code, and refuses every code after", async () => {
		const last = await verifying(CODE, setOf(CODE));
		expect(last).toEqual({ ok: true, factorId: "f-set", next: { codes: [] } });

		expect(await verifying(CODE, { codes: [] })).toEqual({ ok: false, reason: "invalid" });
	});

	it("throws, never refusing the code, when a digest names a key the ring no longer holds", async () => {
		const gone = createMfaSealing({ ring: [{ id: "k-gone", key: randomBytes(32) }] }).digestsFor(
			RECOVERY_CODE_FACTOR_KIND,
		);
		const data = { codes: [gone.digest([CODE]), gone.digest([OTHER])] };

		await expect(verifying(CODE, data)).rejects.toThrow();
		await expect(verifying("ZZZZ-ZZZZ-ZZZZ-ZZZZ", data)).rejects.toThrow();
	});

	it("throws on data that is not a set of keyed digests", async () => {
		for (const data of [{}, { codes: "x" }, { codes: [{ keyId: "k1" }] }]) {
			await expect(verifying(CODE, data), JSON.stringify(data)).rejects.toThrow();
		}
	});
});

describe("recoveryCodesLeft", () => {
	const factor = createRecoveryCodeFactor({ count: 10 });
	const digests = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] }).digestsFor(
		RECOVERY_CODE_FACTOR_KIND,
	);

	it("counts the codes a set holds", () => {
		const set = generateRecoveryCodes(factor, digests);
		expect(set && recoveryCodesLeft(factor, set.data)).toBe(10);
		expect(recoveryCodesLeft(factor, { codes: [] })).toBe(0);
	});

	it("counts none in data that is not a set", () => {
		expect(recoveryCodesLeft(factor, {})).toBe(0);
		expect(recoveryCodesLeft(factor, { codes: "x" })).toBe(0);
	});

	it("says nothing for a factor this package's recovery-code module did not make", () => {
		const settings = { algorithm: "SHA1", digits: 6, period: 30, window: 1, issuer: "x" } as const;
		expect(recoveryCodesLeft(createTotpFactor(settings), { codes: [] })).toBeUndefined();
		expect(recoveryCodesLeft({ ...factor }, { codes: [] })).toBeUndefined();
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

describe("issueRecoveryCodes", () => {
	const ring = [{ id: "k1", key: randomBytes(32) }];
	const sealing = createMfaSealing({ ring });
	const resolverOf = (...factors: MfaFactor[]): MfaFactorResolver => ({
		get: (kind) => factors.find((factor) => factor.kind === kind),
		entries: function* () {
			for (const factor of factors) yield [factor.kind, factor] as const;
		},
	});
	const issue = (options: Partial<Parameters<typeof issueRecoveryCodes>[0]> = {}) =>
		issueRecoveryCodes({
			factors: resolverOf(createRecoveryCodeFactor({ count: 10 })),
			factorStore: createMemoryMfaFactorStore(),
			sealing,
			subject: "u-alice",
			binding: "email_proof",
			nowMs: 1_900_000_000_000,
			...options,
		});

	it("writes one record holding the set, as the binding it follows authorized it, and answers the codes once", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const issued = await issue({ factorStore });
		expect(issued).toEqual({ issued: true, codes: expect.any(Array) });
		const [record, ...rest] = await factorStore.list("u-alice");
		expect(rest).toEqual([]);
		expect(record).toMatchObject({
			kind: RECOVERY_CODE_FACTOR_KIND,
			binding: "email_proof",
			label: undefined,
			version: 0,
			createdAt: new Date(1_900_000_000_000),
		});
		const opened = record === undefined ? undefined : sealing.openFactorData(record, record.data);
		expect(opened?.state).toBe("ok");
	});

	it("issues nothing while the factor is off, or when the kind is another package's factor", async () => {
		const factorStore = createMemoryMfaFactorStore();
		expect(await issue({ factors: resolverOf(), factorStore })).toBeUndefined();
		expect(
			await issue({
				factors: resolverOf({ ...createRecoveryCodeFactor({ count: 10 }) }),
				factorStore,
			}),
		).toBeUndefined();
		expect(await factorStore.list("u-alice")).toEqual([]);
	});

	it("never throws: a set that cannot be made or written answers not issued, with why", async () => {
		const down = new Error("factor store unreachable");
		const failingStore = {
			...createMemoryMfaFactorStore(),
			create: async () => {
				throw down;
			},
		};
		expect(await issue({ factorStore: failingStore })).toEqual({ issued: false, cause: down });
		const broken = new RangeError("no digest");
		const brokenSealing = {
			...sealing,
			digestsFor: () => {
				throw broken;
			},
		};
		expect(await issue({ sealing: brokenSealing })).toEqual({ issued: false, cause: broken });
	});
});

describe("issueRecoveryCodes, replacing a set", () => {
	const ring = [{ id: "k1", key: randomBytes(32) }];
	const sealing = createMfaSealing({ ring });
	const factors: MfaFactorResolver = {
		get: (kind) => (kind === RECOVERY_CODE_FACTOR_KIND ? factor : undefined),
		entries: function* () {
			yield [RECOVERY_CODE_FACTOR_KIND, factor] as const;
		},
	};
	const factor = createRecoveryCodeFactor({ count: 10 });
	const standing = (factorStore: MfaFactorStore, id = "old-set") =>
		factorStore.create({
			id,
			subject: "u-alice",
			kind: RECOVERY_CODE_FACTOR_KIND,
			label: undefined,
			binding: "password",
			createdAt: new Date(0),
			lastUsedAt: undefined,
			version: 0,
			data: "sealed",
		});
	const replace = (factorStore: MfaFactorStore) =>
		issueRecoveryCodes({
			factors,
			factorStore,
			sealing,
			subject: "u-alice",
			binding: "email_proof",
			nowMs: 1_900_000_000_000,
			replace: true,
		});

	it("writes the new set, then removes the subject's other sets: regenerated", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await standing(factorStore);
		const create = vi.spyOn(factorStore, "create");
		const remove = vi.spyOn(factorStore, "remove");

		expect(await replace(factorStore)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: true,
		});
		const records = await factorStore.list("u-alice");
		expect(records).toHaveLength(1);
		expect(records[0]?.id).not.toBe("old-set");
		expect(create.mock.invocationCallOrder[0]).toBeLessThan(
			remove.mock.invocationCallOrder[0] ?? 0,
		);
	});

	it("is not regenerated when no other set stood", async () => {
		const factorStore = createMemoryMfaFactorStore();
		expect(await replace(factorStore)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: false,
		});
		expect(await factorStore.list("u-alice")).toHaveLength(1);
	});

	it("leaves the old set standing when it cannot be removed, and says why: the new one is issued", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await standing(factorStore);
		const down = new Error("remove failed");
		vi.spyOn(factorStore, "remove").mockRejectedValue(down);

		expect(await replace(factorStore)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: true,
			unreplaced: down,
		});
		expect(await factorStore.list("u-alice")).toHaveLength(2);
	});

	it("says why when the sets cannot be listed after the write, regenerated as one may stand", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const down = new Error("list failed");
		vi.spyOn(factorStore, "list").mockRejectedValue(down);

		expect(await replace(factorStore)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: true,
			unreplaced: down,
		});
	});

	it("removes no record of another kind", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create({
			id: "totp-1",
			subject: "u-alice",
			kind: "totp",
			label: undefined,
			binding: "password",
			createdAt: new Date(0),
			lastUsedAt: undefined,
			version: 0,
			data: "sealed",
		});
		await replace(factorStore);
		expect((await factorStore.list("u-alice")).map((record) => record.kind).sort()).toEqual([
			RECOVERY_CODE_FACTOR_KIND,
			"totp",
		]);
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

	it("succeeds once when the same code is given in two logins at once: the loser spends its transaction, never a code", async () => {
		const memory = createMemoryMfaFactorStore();
		await seedTotp(memory);
		const set = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			suiteSealing().digestsFor(RECOVERY_CODE_FACTOR_KIND),
		);
		if (set === undefined) throw new Error("no set");
		const record = await seedFactor(memory, RECOVERY_CODE_FACTOR_KIND, set.data);
		// Each write waits for the other: both verified the code before either spent it.
		let arrived = 0;
		let bothArrived: () => void = () => undefined;
		const both = new Promise<void>((resolve) => {
			bothArrived = resolve;
		});
		const factorStore: MfaFactorStore = {
			...memory,
			update: async (...args) => {
				arrived += 1;
				if (arrived === 2) bothArrived();
				if (arrived <= 2) await both;
				return memory.update(...args);
			},
		};
		const { app, userSessionStore, transactionStore } = await boot({
			config: configFor("required"),
			factorStore,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const logins = [await beginLogin(app), await beginLogin(app)];

		const answers = await Promise.all(
			logins.map(({ agent, transaction }) => verify(agent, transaction, record.id, set.codes[0])),
		);

		expect(answers.map((res) => res.status).sort()).toEqual([200, 401]);
		expect(answers.find((res) => res.status === 401)?.body).toMatchObject({
			error: "mfa_invalid",
			attempts_remaining: 0,
		});
		expect(create).toHaveBeenCalledTimes(1);
		for (const { transaction } of logins)
			expect(await transactionStore.get(transaction)).toBeNull();
		const stored = (await factorStore.list("u-alice")).find((entry) => entry.id === record.id);
		const opened = stored && suiteSealing().openFactorData(stored, stored.data);
		expect(opened?.state === "ok" && (opened.value.codes as unknown[]).length).toBe(2);
	});

	it("is answered 503 once — mfa_factor_unreadable, the verification — and no session, when the set's key left the ring", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const gone = createMfaSealing({ ring: [{ id: "k-gone", key: randomBytes(32) }] });
		const set = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			gone.digestsFor(RECOVERY_CODE_FACTOR_KIND),
		);
		if (set === undefined) throw new Error("no set");
		const record = await seedFactor(factorStore, RECOVERY_CODE_FACTOR_KIND, set.data);
		const { app, logger, userSessionStore } = await boot({
			config: configFor("required"),
			factorStore,
		});
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await verify(agent, transaction, record.id, set.codes[0]);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			kind: RECOVERY_CODE_FACTOR_KIND,
			state: "verification",
		});
		expect(create).not.toHaveBeenCalled();
	});
});
