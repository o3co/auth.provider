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
	recoverySetGeneration,
	recoverySetRefusal,
	recoverySetShown,
} from "#/recovery/factor.mjs";
import { issueRecoveryCodes, writeRecoveryCodes } from "#/recovery/issue.mjs";
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

	it("keeps the set's generation and whether it was shown in the set it answers", async () => {
		const data = { ...setOf(CODE, OTHER), generation: 3, shown: true };

		expect(await verifying(CODE, data)).toEqual({
			ok: true,
			factorId: "f-set",
			next: { codes: [digests.digest([OTHER])], generation: 3, shown: true },
		});
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

describe("a recovery-code set's generation and whether it was shown", () => {
	const factor = createRecoveryCodeFactor({ count: 10 });
	const sealing = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] });
	const digest = sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND).digest(["0123456789ABCDEF"]);
	const totp = createTotpFactor({
		algorithm: "SHA1",
		digits: 6,
		period: 30,
		window: 1,
		issuer: "x",
	});

	it("reads a set's generation and whether it was shown as it holds them", () => {
		const data = { codes: [digest], generation: 4, shown: false };
		expect(recoverySetGeneration(factor, data)).toBe(4);
		expect(recoverySetShown(factor, data)).toBe(false);
	});

	it("reads a set written before either was kept as generation 0, shown when it was issued", () => {
		const data = { codes: [digest] };
		expect(recoverySetGeneration(factor, data)).toBe(0);
		expect(recoverySetShown(factor, data)).toBe(true);
	});

	it("reads nothing from data that is not a set, a generation that is no whole number, or another factor", () => {
		for (const data of [
			{},
			{ codes: "x" },
			{ codes: [digest], generation: -1 },
			{ codes: [digest], generation: 1.5 },
			{ codes: [digest], generation: "2" },
			{ codes: [digest], generation: 1, shown: "yes" },
		]) {
			expect(recoverySetGeneration(factor, data), JSON.stringify(data)).toBeUndefined();
			expect(recoverySetShown(factor, data), JSON.stringify(data)).toBeUndefined();
		}
		expect(recoverySetGeneration(totp, { codes: [digest], generation: 1 })).toBeUndefined();
		expect(recoverySetGeneration({ ...factor }, { codes: [digest] })).toBeUndefined();
	});
});

describe("recoverySetRefusal, the one rule a verification holds a set to", () => {
	const factor = createRecoveryCodeFactor({ count: 10 });
	const sealing = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] });
	const digests = sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND);
	const held = (keyId: string) => keyId === "k1";

	it("refuses a set below the subject's recovery-set floor, and none at or above it", () => {
		const set = generateRecoveryCodes(factor, digests, 2);
		if (set === undefined) throw new Error("no set");
		expect(recoverySetRefusal(factor, set.data, { floor: 3, holdsKey: held })).toEqual({
			reason: "retired",
		});
		expect(recoverySetRefusal(factor, set.data, { floor: 2, holdsKey: held })).toBeUndefined();
		expect(recoverySetRefusal(factor, set.data, { floor: 0, holdsKey: held })).toBeUndefined();
	});

	it("reads a set written before generations were kept as generation 0: refused once any floor was raised", () => {
		const data = { codes: [digests.digest(["0123456789ABCDEF"])] };
		expect(recoverySetRefusal(factor, data, { floor: 0, holdsKey: held })).toBeUndefined();
		expect(recoverySetRefusal(factor, data, { floor: 1, holdsKey: held })).toEqual({
			reason: "retired",
		});
	});

	it("names the key a digest needs that the ring no longer holds", () => {
		const gone = createMfaSealing({ ring: [{ id: "k-gone", key: randomBytes(32) }] }).digestsFor(
			RECOVERY_CODE_FACTOR_KIND,
		);
		const set = generateRecoveryCodes(factor, gone, 1);
		if (set === undefined) throw new Error("no set");
		expect(recoverySetRefusal(factor, set.data, { floor: 0, holdsKey: held })).toEqual({
			reason: "key_unavailable",
			keyId: "k-gone",
		});
	});

	it("refuses nothing of another factor's data, nor data that is not a set, which the verification answers", () => {
		const totp = createTotpFactor({
			algorithm: "SHA1",
			digits: 6,
			period: 30,
			window: 1,
			issuer: "x",
		});
		expect(recoverySetRefusal(totp, { secret: "x" }, { floor: 9, holdsKey: held })).toBeUndefined();
		expect(recoverySetRefusal(factor, {}, { floor: 9, holdsKey: held })).toBeUndefined();
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

	it("issues a set of the generation asked, not yet shown; one asked no generation is of generation 0", () => {
		const factor = createRecoveryCodeFactor({ count: 2 });
		expect(generateRecoveryCodes(factor, digests, 7)?.data).toMatchObject({
			generation: 7,
			shown: false,
		});
		expect(generateRecoveryCodes(factor, digests)?.data).toMatchObject({
			generation: 0,
			shown: false,
		});
	});

	it("issues nothing for a factor this package's recovery-code module did not make", () => {
		const settings = { algorithm: "SHA1", digits: 6, period: 30, window: 1, issuer: "x" } as const;
		expect(generateRecoveryCodes(createTotpFactor(settings), digests)).toBeUndefined();
		expect(
			generateRecoveryCodes({ ...createRecoveryCodeFactor({ count: 10 }) }, digests),
		).toBeUndefined();
	});
});

/** The subject's recovery-set floor as a lease hands it to issuing: read, and raised, never lowered. */
function floorAt(initial = 0) {
	let floor = initial;
	return {
		get value() {
			return floor;
		},
		read: vi.fn(async (_subject: string) => floor),
		raise: vi.fn(async (_subject: string, setGeneration: number) => {
			floor = Math.max(floor, setGeneration);
		}),
	};
}

describe("issueRecoveryCodes", () => {
	const ring = [{ id: "k1", key: randomBytes(32) }];
	const sealing = createMfaSealing({ ring });
	const resolverOf = (...factors: MfaFactor[]): MfaFactorResolver => ({
		get: (kind) => factors.find((factor) => factor.kind === kind),
		entries: function* () {
			for (const factor of factors) yield [factor.kind, factor] as const;
		},
	});
	const issue = (
		options: Partial<Omit<Parameters<typeof issueRecoveryCodes>[0], "writes">> & {
			readonly factorStore?: MfaFactorStore;
			readonly floor?: ReturnType<typeof floorAt>;
		} = {},
	) => {
		const { factorStore, floor, ...rest } = options;
		return issueRecoveryCodes({
			factors: resolverOf(createRecoveryCodeFactor({ count: 10 })),
			writes: {
				factorStore: factorStore ?? createMemoryMfaFactorStore(),
				recoverySetFloor: floor ?? floorAt(),
			},
			sealing,
			subject: "u-alice",
			binding: "email_proof",
			nowMs: 1_900_000_000_000,
			...rest,
		});
	};

	it("writes one record holding the set, as the binding it follows authorized it, shown, and answers the codes once", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const issued = await issue({ factorStore });
		expect(issued).toEqual({ issued: true, codes: expect.any(Array), regenerated: false });
		const [record, ...rest] = await factorStore.list("u-alice");
		expect(rest).toEqual([]);
		expect(record).toMatchObject({
			kind: RECOVERY_CODE_FACTOR_KIND,
			binding: "email_proof",
			label: undefined,
			version: 1,
			createdAt: new Date(1_900_000_000_000),
		});
		const opened = record === undefined ? undefined : sealing.openFactorData(record, record.data);
		expect(opened?.state === "ok" && opened.value).toMatchObject({ generation: 1, shown: true });
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

describe("writeRecoveryCodes", () => {
	const sealing = createMfaSealing({ ring: [{ id: "k1", key: randomBytes(32) }] });
	const factor = createRecoveryCodeFactor({ count: 10 });
	const factors: MfaFactorResolver = {
		get: (kind) => (kind === RECOVERY_CODE_FACTOR_KIND ? factor : undefined),
		entries: function* () {
			yield [RECOVERY_CODE_FACTOR_KIND, factor] as const;
		},
	};
	const write = (factorStore: MfaFactorStore, markedThrough: MfaFactorStore = factorStore) =>
		writeRecoveryCodes({
			factors,
			writes: { factorStore, recoverySetFloor: floorAt() },
			sealing,
			subject: "u-alice",
			binding: "email_proof",
			nowMs: 1_900_000_000_000,
			markedThrough,
		});
	/** The subject's one set as stored: its version, and whether it was shown. */
	const storedSet = async (factorStore: MfaFactorStore) => {
		const [record, ...rest] = await factorStore.list("u-alice");
		expect(rest).toEqual([]);
		if (record === undefined) throw new Error("no set");
		const opened = sealing.openFactorData(record, record.data);
		return {
			version: record.version,
			shown: opened.state === "ok" ? opened.value.shown : "unreadable",
		};
	};

	it("writes the set unshown, its codes reached only by show, which marks it shown through the store it names", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const outside = createMemoryMfaFactorStore();
		const update = vi
			.spyOn(outside, "update")
			.mockImplementation(factorStore.update.bind(factorStore));

		const written = await write(factorStore, outside);

		expect(written).toEqual({ issued: "unshown", show: expect.any(Function) });
		expect(await storedSet(factorStore)).toEqual({ version: 0, shown: false });
		if (written?.issued !== "unshown") throw new Error("not written");
		const shown = await written.show();
		expect(shown).toEqual({ issued: true, codes: expect.any(Array), regenerated: false });
		expect(update).toHaveBeenCalledTimes(1);
		expect(await storedSet(factorStore)).toEqual({ version: 1, shown: true });
	});

	it("answers the codes once: a second show finds the set changed and answers none", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const written = await write(factorStore);
		if (written?.issued !== "unshown") throw new Error("not written");
		expect((await written.show()).issued).toBe(true);

		const again = await written.show();

		expect(again).toEqual({ issued: false, cause: expect.any(Error) });
		expect(again).not.toHaveProperty("codes");
		expect(await storedSet(factorStore)).toEqual({ version: 1, shown: true });
	});

	it("answers no codes, and never throws, when the set was removed or the mark fails: the set left unshown", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const removed = await write(factorStore);
		if (removed?.issued !== "unshown") throw new Error("not written");
		const [record] = await factorStore.list("u-alice");
		if (record === undefined) throw new Error("no set");
		await factorStore.remove("u-alice", record.id);
		expect(await removed.show()).toEqual({ issued: false, cause: expect.any(Error) });

		const down = new Error("factor store unreachable");
		const failing = { ...factorStore, update: vi.fn().mockRejectedValue(down) };
		const unmarked = await write(factorStore, failing);
		if (unmarked?.issued !== "unshown") throw new Error("not written");
		expect(await unmarked.show()).toEqual({ issued: false, cause: down });
		expect(await storedSet(factorStore)).toEqual({ version: 0, shown: false });
	});
});

describe("issueRecoveryCodes, replacing the sets that stood", () => {
	const ring = [{ id: "k1", key: randomBytes(32) }];
	const sealing = createMfaSealing({ ring });
	const factor = createRecoveryCodeFactor({ count: 10 });
	const factors: MfaFactorResolver = {
		get: (kind) => (kind === RECOVERY_CODE_FACTOR_KIND ? factor : undefined),
		entries: function* () {
			yield [RECOVERY_CODE_FACTOR_KIND, factor] as const;
		},
	};
	const digests = sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND);
	/** A record of `kind` (a recovery-code set by default) whose data is `data` sealed to it, or what no key opens. */
	const recordOf = (
		id: string,
		options: {
			readonly kind?: string;
			readonly data?: Record<string, unknown>;
			readonly createdAt?: Date;
		} = {},
	) => {
		const kind = options.kind ?? RECOVERY_CODE_FACTOR_KIND;
		return {
			id,
			subject: "u-alice",
			kind,
			label: undefined,
			binding: "password" as const,
			createdAt: options.createdAt ?? new Date(0),
			lastUsedAt: undefined,
			version: 0,
			data:
				options.data === undefined
					? "sealed"
					: sealing.sealFactorData({ subject: "u-alice", id, kind }, options.data),
		};
	};
	/** A set of `generation`, shown. */
	const setAt = (generation: number) => ({
		...(generateRecoveryCodes(factor, digests, generation)?.data ?? {}),
		shown: true,
	});
	const issue = (
		factorStore: MfaFactorStore,
		binding: "email_proof" | "password" | "mfa" = "email_proof",
		floor = floorAt(),
		listed?: Parameters<typeof issueRecoveryCodes>[0]["listed"],
	) =>
		issueRecoveryCodes({
			factors,
			writes: { factorStore, recoverySetFloor: floor },
			sealing,
			subject: "u-alice",
			binding,
			nowMs: 1_900_000_000_000,
			...(listed === undefined ? {} : { listed }),
		});
	/** The subject's sets as stored, each with its generation and whether it was shown. */
	const setsIn = async (factorStore: MfaFactorStore) =>
		(await factorStore.list("u-alice"))
			.filter((record) => record.kind === RECOVERY_CODE_FACTOR_KIND)
			.map((record) => {
				const opened = sealing.openFactorData(record, record.data);
				return {
					id: record.id,
					generation: opened.state === "ok" ? opened.value.generation : "unreadable",
					shown: opened.state === "ok" ? opened.value.shown : "unreadable",
				};
			});

	it("writes the new set one generation past the newest it can read and the floor, raises the floor to it, removes the sets that stood, then shows it", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("old-set", { data: setAt(2) }));
		const floor = floorAt(3);
		const create = vi.spyOn(factorStore, "create");
		const remove = vi.spyOn(factorStore, "remove");
		const list = vi.spyOn(factorStore, "list");
		const update = vi.spyOn(factorStore, "update");

		expect(await issue(factorStore, "email_proof", floor)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: true,
		});
		expect(floor.raise).toHaveBeenCalledWith("u-alice", 4);
		expect(floor.value).toBe(4);
		expect(await setsIn(factorStore)).toEqual([
			{ id: expect.any(String), generation: 4, shown: true },
		]);
		const order = [
			list.mock.invocationCallOrder[0],
			create.mock.invocationCallOrder[0],
			floor.raise.mock.invocationCallOrder[0],
			remove.mock.invocationCallOrder[0],
			list.mock.invocationCallOrder[1],
			update.mock.invocationCallOrder[0],
		];
		expect(order.every((at) => at !== undefined)).toBe(true);
		expect([...order].sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual(order);
	});

	it("replaces as a regeneration (bound by mfa) does, and as a binding by the account-email proof does", async () => {
		for (const binding of ["mfa", "email_proof"] as const) {
			const factorStore = createMemoryMfaFactorStore();
			await factorStore.create(recordOf("old-set", { data: setAt(1) }));
			const floor = floorAt(1);
			await issue(factorStore, binding, floor);
			expect(floor.value, binding).toBe(2);
			expect(
				(await setsIn(factorStore)).map((set) => set.generation),
				binding,
			).toEqual([2]);
		}
	});

	it("counts no set it cannot read toward the newest, and removes it with the rest", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("unreadable-set"));
		await factorStore.create(recordOf("old-set", { data: setAt(1) }));
		const floor = floorAt(1);

		await issue(factorStore, "email_proof", floor);

		expect(await setsIn(factorStore)).toEqual([
			{ id: expect.any(String), generation: 2, shown: true },
		]);
	});

	it("reads a set written before generations were kept as generation 0", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(
			recordOf("legacy-set", { data: { codes: [digests.digest(["0123456789ABCDEF"])] } }),
		);
		await issue(factorStore);
		expect((await setsIn(factorStore)).map((set) => set.generation)).toEqual([1]);
	});

	it("never removes a set written after its listing, such as one another binding issued", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("old-set"));
		const create = factorStore.create.bind(factorStore);
		vi.spyOn(factorStore, "create").mockImplementation(async (record) => {
			await create(recordOf("later-set"));
			return create(record);
		});

		await issue(factorStore);

		const ids = (await factorStore.list("u-alice")).map((record) => record.id);
		expect(ids).toContain("later-set");
		expect(ids).not.toContain("old-set");
	});

	it("is not regenerated when no other set stood", async () => {
		const factorStore = createMemoryMfaFactorStore();
		expect(await issue(factorStore)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: false,
		});
		expect(await factorStore.list("u-alice")).toHaveLength(1);
	});

	it("keeps the sets that stood for a binding by password, writing its set at the newest generation beside them, the floor untouched, and says why", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("old-set", { data: setAt(2) }));
		const floor = floorAt(2);
		const remove = vi.spyOn(factorStore, "remove");

		expect(await issue(factorStore, "password", floor)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: true,
			unreplaced: { kept: "password_binding" },
		});
		expect(remove).not.toHaveBeenCalled();
		expect(floor.raise).not.toHaveBeenCalled();
		expect((await setsIn(factorStore)).map((set) => set.generation)).toEqual([2, 2]);
	});

	it("leaves an old set stored when it cannot be removed — below the floor, so dead — and says why, a rejection with no reason included", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("old-set", { data: setAt(0) }));
		vi.spyOn(factorStore, "remove").mockRejectedValue(undefined);
		const floor = floorAt();

		const issued = await issue(factorStore, "email_proof", floor);

		expect(issued).toMatchObject({ issued: true, regenerated: true });
		const unreplaced = (issued as { unreplaced?: object }).unreplaced;
		expect(unreplaced !== undefined && "cause" in unreplaced).toBe(true);
		expect(await factorStore.list("u-alice")).toHaveLength(2);
		expect(floor.value).toBe(1);
	});

	it("writes the new set past the floor when the sets cannot be listed first, regenerated as one may stand, and says why", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const down = new Error("list failed");
		vi.spyOn(factorStore, "list").mockRejectedValueOnce(down);
		const remove = vi.spyOn(factorStore, "remove");
		const floor = floorAt(5);

		expect(await issue(factorStore, "email_proof", floor)).toEqual({
			issued: true,
			codes: expect.any(Array),
			regenerated: true,
			unreplaced: { cause: down },
		});
		expect(remove).not.toHaveBeenCalled();
		expect(floor.value).toBe(6);
		expect(await factorStore.list("u-alice")).toHaveLength(1);
	});

	it("takes the records its caller read under the same lease, listing them no more before the write", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const old = recordOf("old-set", { data: setAt(1) });
		await factorStore.create(old);
		const list = vi.spyOn(factorStore, "list");
		const create = vi.spyOn(factorStore, "create");

		await issue(factorStore, "mfa", floorAt(1), [old]);

		expect(list.mock.invocationCallOrder[0] ?? 0).toBeGreaterThan(
			create.mock.invocationCallOrder[0] ?? 0,
		);
		expect((await setsIn(factorStore)).map((set) => set.generation)).toEqual([2]);
	});

	it("writes nothing when the floor cannot be read, and says why", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("old-set", { data: setAt(1) }));
		const down = new Error("transaction store unreachable");
		const floor = floorAt(1);
		floor.read.mockRejectedValueOnce(down);

		expect(await issue(factorStore, "email_proof", floor)).toEqual({ issued: false, cause: down });
		expect((await factorStore.list("u-alice")).map((record) => record.id)).toEqual(["old-set"]);
	});

	it("removes its own set and keeps the sets that stood when the floor cannot be raised", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("old-set", { data: setAt(1) }));
		const down = new Error("the lease was not held");
		const floor = floorAt(1);
		floor.raise.mockRejectedValueOnce(down);

		expect(await issue(factorStore, "mfa", floor)).toEqual({ issued: false, cause: down });
		expect((await factorStore.list("u-alice")).map((record) => record.id)).toEqual(["old-set"]);
		expect(floor.value).toBe(1);
	});

	it.each([
		["an earlier set at its generation", 2, new Date(0)],
		["a set at a later generation", 3, new Date(2_000_000_000_000)],
	])(
		"loses to %s read after its write: removes its own, unshown, and says it lost",
		async (_, generation, createdAt) => {
			const factorStore = createMemoryMfaFactorStore();
			await factorStore.create(recordOf("old-set", { data: setAt(1) }));
			const create = factorStore.create.bind(factorStore);
			vi.spyOn(factorStore, "create").mockImplementation(async (record) => {
				await create(record);
				await create(recordOf("other-set", { data: setAt(generation), createdAt }));
			});
			const update = vi.spyOn(factorStore, "update");

			const issued = await issue(factorStore, "mfa", floorAt(1));

			expect(issued).toMatchObject({ issued: false, conflict: true });
			expect(update).not.toHaveBeenCalled();
			expect((await factorStore.list("u-alice")).map((record) => record.id)).toEqual(["other-set"]);
		},
	);

	it("yields to a set at its generation dated after its own: whichever writer reads the other after its write loses, so two never both stand", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const create = factorStore.create.bind(factorStore);
		vi.spyOn(factorStore, "create").mockImplementation(async (record) => {
			await create(record);
			await create(
				recordOf("later-set", { data: setAt(1), createdAt: new Date(2_000_000_000_000) }),
			);
		});

		expect(await issue(factorStore, "mfa", floorAt())).toMatchObject({
			issued: false,
			conflict: true,
		});
		expect((await factorStore.list("u-alice")).map((record) => record.id)).toEqual(["later-set"]);
	});

	it("stands beside a set below its generation another writer left, and a set it cannot read", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const create = factorStore.create.bind(factorStore);
		vi.spyOn(factorStore, "create").mockImplementation(async (record) => {
			await create(record);
			await create(recordOf("older-set", { data: setAt(1) }));
			await create(recordOf("unreadable-set"));
		});

		expect(await issue(factorStore, "mfa", floorAt(1))).toMatchObject({ issued: true });
	});

	it("shows nothing when the records cannot be read again after its write", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const down = new Error("list failed");
		const list = factorStore.list.bind(factorStore);
		vi.spyOn(factorStore, "list").mockImplementationOnce(list).mockRejectedValueOnce(down);

		expect(await issue(factorStore, "mfa")).toEqual({ issued: false, cause: down });
		expect((await setsIn(factorStore)).map((set) => set.shown)).toEqual([false]);
	});

	it.each([
		["lost", async () => null],
		[
			"failed",
			async () => {
				throw new Error("update failed");
			},
		],
		["answered outside the port", async () => ({ id: "elsewhere" })],
	])(
		"answers no codes, the set left unshown, when the write that shows it is %s",
		async (_, update) => {
			const factorStore = createMemoryMfaFactorStore();
			vi.spyOn(factorStore, "update").mockImplementation(update as never);

			expect(await issue(factorStore, "mfa")).toMatchObject({ issued: false });
			expect((await setsIn(factorStore)).map((set) => set.shown)).toEqual([false]);
		},
	);

	it("lets two writers the lease admitted together both yield when each reads the other after its write: no new set left, never two", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const floor = floorAt();
		const create = factorStore.create.bind(factorStore);
		let arrived = 0;
		let release: () => void = () => undefined;
		const both = new Promise<void>((resolve) => {
			release = resolve;
		});
		vi.spyOn(factorStore, "create").mockImplementation(async (record) => {
			await create(record);
			// Each writer's set is written before either reads the records again.
			arrived += 1;
			if (arrived === 2) release();
			await both;
		});

		const [a, b] = await Promise.all([
			issue(factorStore, "mfa", floor),
			issue(factorStore, "mfa", floor),
		]);

		expect(a).toMatchObject({ issued: false, conflict: true });
		expect(b).toMatchObject({ issued: false, conflict: true });
		expect(await setsIn(factorStore)).toEqual([]);
	});

	it("says both failures when the floor cannot be raised and its own set cannot be removed: the set stays stored, unshown", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const floor = floorAt(1);
		const raised = new Error("the lease was not held");
		const unremoved = new Error("remove failed");
		floor.raise.mockRejectedValueOnce(raised);
		vi.spyOn(factorStore, "remove").mockRejectedValueOnce(unremoved);

		const issued = await issue(factorStore, "mfa", floor);

		expect(issued).toMatchObject({ issued: false });
		const cause = (issued as { cause?: unknown }).cause;
		expect(cause).toBeInstanceOf(AggregateError);
		expect((cause as AggregateError).errors).toEqual([raised, unremoved]);
		expect((await setsIn(factorStore)).map((set) => set.shown)).toEqual([false]);
	});

	it("removes no record of another kind", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await factorStore.create(recordOf("totp-1", { kind: "totp" }));
		await issue(factorStore);
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

	it("is answered 503 once — mfa_factor_unreadable, naming the key the set's digests need — and no session or attempt spent, when that key left the ring", async () => {
		const factorStore = createMemoryMfaFactorStore();
		await seedTotp(factorStore);
		const gone = createMfaSealing({ ring: [{ id: "k-gone", key: randomBytes(32) }] });
		const set = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			gone.digestsFor(RECOVERY_CODE_FACTOR_KIND),
		);
		if (set === undefined) throw new Error("no set");
		const record = await seedFactor(factorStore, RECOVERY_CODE_FACTOR_KIND, set.data);
		const { app, logger, userSessionStore, transactionStore } = await boot({
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
			factorId: record.id,
			state: "key_unavailable",
			keyId: "k-gone",
		});
		expect(create).not.toHaveBeenCalled();
		expect((await transactionStore.get(transaction))?.attempts).toBe(0);
	});
});
