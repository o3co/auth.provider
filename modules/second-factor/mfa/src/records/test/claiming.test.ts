import { isUnavailable } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import type { FactorStore, StoredFactors } from "../../store.ts";
import { updatingAsOne } from "../../testing.ts";
import { portsRefused } from "../ports.ts";
import { claimKeyOf, type Factor, factorRecords, listKeyOf, storedList } from "../records.ts";

const factor = (id: string): Factor => ({ id, kind: "card", secret: "", state: null });
const claim = { kind: "card", value: "c-1" };

/** A factor store offering `updateAsOne` over the records stand-in, as a Store on subject-records does. */
function asOne() {
	const stand = memoryRecords<StoredFactors>(() => 0, { shards: 1, perShard: 1 });
	const store: FactorStore = {
		save: (key, record) => stand.records.create(key, record, "endless"),
		read: stand.records.read,
		update: stand.records.change,
		scan: stand.records.scan,
		updateAsOne: updatingAsOne(stand.records),
	};
	return { store, records: factorRecords(store), peek: stand.peek };
}
const binding = (id: string) => (all: readonly Factor[]) => ({
	next: [...all, factor(id)],
	verdict: "bound" as const,
});

it("writes a first factor's list and its claim as one, and takes a stale claim over, by a change as one", async () => {
	const { records, peek } = asOne();
	expect(await records.decideClaiming("ann", { ...claim, factor: "f1" }, binding("f1"))).toBe(
		"bound",
	);
	expect(peek(claimKeyOf("card", "c-1"))).toEqual({ listKey: listKeyOf("ann"), factor: "f1" });
	expect(peek(listKeyOf("ann"))).toMatchObject({ subject: "ann", factors: [{ id: "f1" }] });
	// ann's factor gone, her claim is stale: bob's binding takes it over, ann's list left as it is.
	await records.decide("ann", () => ({ next: [], verdict: "cleared" }));
	expect(await records.decideClaiming("bob", { ...claim, factor: "f2" }, binding("f2"))).toBe(
		"bound",
	);
	expect(peek(claimKeyOf("card", "c-1"))).toEqual({ listKey: listKeyOf("bob"), factor: "f2" });
	expect(peek(listKeyOf("ann"))).toMatchObject({ factors: [] });
	// Held by a factor its list still lists: a duplicate, nothing written.
	expect(await records.decideClaiming("cy", { ...claim, factor: "f3" }, binding("f3"))).toBe(
		"duplicate",
	);
	expect(peek(listKeyOf("cy"))).toBeUndefined();
});

it("reads a refusal before any verdict, unavailable and never tried again, and refuses an erased subject's first list the same", async () => {
	const { store } = asOne();
	let asked = 0;
	const refusing: FactorStore = {
		...store,
		updateAsOne: async () => {
			asked += 1;
			return { kind: "refused", at: { in: "targets", nth: 0 }, why: "erased" };
		},
	};
	const judged = factorRecords(refusing).decideClaiming("erin", { ...claim, factor: "f" }, () => {
		throw new Error("judged");
	});
	await expect(judged).rejects.toSatisfy(isUnavailable);
	expect(asked).toBe(1);
	let updates = 0;
	const erased: FactorStore = {
		...store,
		update: async (...args) => {
			updates += 1;
			return store.update(...args);
		},
		save: async () => "erased",
	};
	await expect(factorRecords(erased).decide("erin", binding("f"))).rejects.toSatisfy(isUnavailable);
	expect(updates).toBe(1);
});

it("states the factor store's ports once: exactly one way to write a list and a claim as one, erase and migrate both or neither", () => {
	const { store } = asOne();
	const { updateAsOne, ...plain } = store;
	const together = { ...plain, updateTogether: async () => ({}) } as unknown as FactorStore;
	expect(portsRefused(store)).toBeUndefined();
	expect(portsRefused(together)).toBeUndefined();
	expect(portsRefused(plain)).toMatch(/exactly one/);
	expect(portsRefused({ ...together, updateAsOne } as FactorStore)).toMatch(/exactly one/);
	const erase = async () => ({}) as never;
	expect(portsRefused({ ...store, erase })).toMatch(/erase and migrate/);
	expect(storedList("x", [])).toEqual({ subject: "x", factors: [] });
});
