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
import type { MfaFactorRecord, MfaFactorStore } from "../factorStore.mjs";

/**
 * The `MfaFactorStore` contract (the MFA ADR's D7), for every adapter.
 *
 * A factor record is the one place a subject's second factors live, and
 * "only zero records open a first binding" (F3) is only as strong as the
 * store: a record that comes back without a field, a version that two
 * writers both win, or a removal that reaches another subject are each a
 * way to lose or forge a factor. `data` is sealed by the coordinator before
 * it reaches the store and is opaque here; the suite holds the store to
 * keeping it byte for byte.
 */
export type MfaFactorStoreContractFactory = () => Promise<MfaFactorStore>;

const RECORD = (overrides: Partial<MfaFactorRecord> = {}): MfaFactorRecord => ({
	id: "factor-1",
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
	version: 1,
	data: "v2.opaque-sealed-data",
	...overrides,
});

const byId = (records: readonly MfaFactorRecord[]): MfaFactorRecord[] =>
	[...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

export function runMfaFactorStoreContract(factory: MfaFactorStoreContractFactory): void {
	describe("MfaFactorStore contract", () => {
		it("lists nothing for a subject with no factor", async () => {
			const store = await factory();
			expect(await store.list("nobody")).toEqual([]);
		});

		it("returns a created record whole, as plain data, its undefined fields named", async () => {
			// Strictly: a key too many, one left out, or a class instance in place
			// of plain data fails here.
			const store = await factory();
			const full = RECORD();
			const bare = RECORD({
				id: "factor-2",
				label: undefined,
				binding: undefined,
				lastUsedAt: undefined,
			});
			await store.create(full);
			await store.create(bare);
			expect(byId(await store.list("user-1"))).toStrictEqual([full, bare]);
		});

		it("keeps data verbatim: the store never reads it", async () => {
			const store = await factory();
			const samples = ["[]", "{}", '{"a":[],"b":{}}', "ü∆ 漢字 🙂", "x".repeat(4096)];
			for (const [i, data] of samples.entries()) {
				await store.create(RECORD({ id: `factor-${i}`, data }));
			}
			const listed = byId(await store.list("user-1"));
			expect(listed.map((r) => r.data)).toEqual(samples);
		});

		it("round-trips every binding and any kind", async () => {
			const store = await factory();
			const records = [
				RECORD({ id: "a", kind: "totp", binding: "password" }),
				RECORD({ id: "b", kind: "email", binding: "email_proof" }),
				RECORD({ id: "c", kind: "webauthn", binding: "mfa" }),
				RECORD({ id: "d", kind: "recovery_code", binding: undefined }),
				RECORD({ id: "e", kind: "acme-contributed", binding: "mfa" }),
			];
			for (const record of records) await store.create(record);
			expect(byId(await store.list("user-1"))).toStrictEqual(records);
		});

		it("refuses a duplicate (subject, id), and keeps the record as it was", async () => {
			const store = await factory();
			await store.create(RECORD());
			await expect(store.create(RECORD({ data: "v2.other", label: "Other" }))).rejects.toThrow();
			expect(await store.list("user-1")).toStrictEqual([RECORD()]);
		});

		it("lets one of N concurrent creates of one (subject, id) through", async () => {
			const store = await factory();
			const results = await Promise.allSettled(
				Array.from({ length: 10 }, (_, i) => store.create(RECORD({ data: `v2.${i}` }))),
			);
			expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
			expect(await store.list("user-1")).toHaveLength(1);
		});

		it("keeps subjects apart: the same id under another subject is another record", async () => {
			const store = await factory();
			const mine = RECORD();
			const theirs = RECORD({ subject: "user-2", data: "v2.theirs" });
			await store.create(mine);
			await store.create(theirs);
			expect(await store.list("user-1")).toStrictEqual([mine]);
			expect(await store.list("user-2")).toStrictEqual([theirs]);
		});

		it("updates at the current version: data, label and lastUsedAt replaced, version + 1, nothing else moved", async () => {
			const store = await factory();
			const record = RECORD();
			await store.create(record);
			const next = {
				data: "v2.re-sealed",
				label: "Work phone",
				lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
			};
			const updated = await store.update("user-1", "factor-1", 1, next);
			const expected = { ...record, ...next, version: 2 };
			expect(updated).toStrictEqual(expected);
			expect(await store.list("user-1")).toStrictEqual([expected]);
		});

		it("clears label and lastUsedAt when the update says undefined", async () => {
			const store = await factory();
			await store.create(RECORD());
			const updated = await store.update("user-1", "factor-1", 1, {
				data: "v2.re-sealed",
				label: undefined,
				lastUsedAt: undefined,
			});
			expect(updated).toStrictEqual({
				...RECORD(),
				data: "v2.re-sealed",
				label: undefined,
				lastUsedAt: undefined,
				version: 2,
			});
			expect(await store.list("user-1")).toStrictEqual([updated]);
		});

		it("answers null for a version that moved, and changes nothing", async () => {
			const store = await factory();
			await store.create(RECORD());
			const next = { data: "v2.late", label: "Late", lastUsedAt: undefined };
			expect(await store.update("user-1", "factor-1", 0, next)).toBeNull();
			expect(await store.update("user-1", "factor-1", 2, next)).toBeNull();
			expect(await store.list("user-1")).toStrictEqual([RECORD()]);
		});

		it("answers null for a record that is gone, and creates nothing", async () => {
			const store = await factory();
			const next = { data: "v2.x", label: undefined, lastUsedAt: undefined };
			expect(await store.update("user-1", "factor-1", 1, next)).toBeNull();
			expect(await store.list("user-1")).toEqual([]);
		});

		it("lets exactly one of N concurrent updates at one version win", async () => {
			const store = await factory();
			await store.create(RECORD());
			const results = await Promise.all(
				Array.from({ length: 10 }, (_, i) =>
					store.update("user-1", "factor-1", 1, {
						data: `v2.writer-${i}`,
						label: `Writer ${i}`,
						lastUsedAt: undefined,
					}),
				),
			);
			const winners = results.filter((r) => r !== null);
			expect(winners).toHaveLength(1);
			expect(await store.list("user-1")).toStrictEqual(winners);
			expect(winners[0]?.version).toBe(2);
		});

		it("never reaches another subject's record through update", async () => {
			const store = await factory();
			await store.create(RECORD({ subject: "user-2" }));
			const next = { data: "v2.forged", label: undefined, lastUsedAt: undefined };
			expect(await store.update("user-1", "factor-1", 1, next)).toBeNull();
			expect(await store.list("user-2")).toStrictEqual([RECORD({ subject: "user-2" })]);
			expect(await store.list("user-1")).toEqual([]);
		});

		it("removes one record, idempotently, leaving the subject's others and other subjects'", async () => {
			const store = await factory();
			await store.create(RECORD({ id: "a" }));
			await store.create(RECORD({ id: "b" }));
			await store.create(RECORD({ id: "a", subject: "user-2" }));
			await store.remove("user-1", "a");
			await store.remove("user-1", "a");
			await store.remove("user-1", "never-was");
			expect(await store.list("user-1")).toStrictEqual([RECORD({ id: "b" })]);
			expect(await store.list("user-2")).toStrictEqual([RECORD({ id: "a", subject: "user-2" })]);
		});

		it("removes every record of one subject, idempotently, and no other subject's", async () => {
			const store = await factory();
			await store.create(RECORD({ id: "a" }));
			await store.create(RECORD({ id: "b" }));
			await store.create(RECORD({ id: "c", subject: "user-2" }));
			await store.removeAllForSubject("user-1");
			await store.removeAllForSubject("user-1");
			await store.removeAllForSubject("nobody");
			expect(await store.list("user-1")).toEqual([]);
			expect(await store.list("user-2")).toStrictEqual([RECORD({ id: "c", subject: "user-2" })]);
		});

		it("takes a record again after it was removed", async () => {
			// A removed factor leaves nothing behind that refuses the next one.
			const store = await factory();
			await store.create(RECORD());
			await store.removeAllForSubject("user-1");
			await store.create(RECORD({ data: "v2.again" }));
			expect(await store.list("user-1")).toStrictEqual([RECORD({ data: "v2.again" })]);
		});
	});
}
