import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { type Factor, factorRecords } from "../src/records/records.ts";
import type { FactorStore, StoredFactors } from "../src/store.ts";
import { memoryFactors } from "./stores.ts";

const factor = (id: string): Factor => ({ id, kind: "code", secret: "", state: null });
const listOf = (...ids: string[]) => ({ factors: ids.map(factor) }) as unknown as StoredFactors;
const added = (id: string) => (all: readonly Factor[]) => ({
	next: [...all, factor(id)],
	verdict: all.length,
});

it("changes the list another request saved first, rather than its own first list", async () => {
	const { factors } = memoryFactors();
	const racing: FactorStore = {
		...factors,
		save: async (key, record, lifetimeMs) => {
			await factors.save(key, listOf("theirs"), lifetimeMs);
			return factors.save(key, record, lifetimeMs);
		},
	};
	// The run written answers: it saw the list the other request saved.
	expect(await factorRecords(racing).decide("sam", added("mine"))).toBe(1);
	expect((await factorRecords(factors).list("sam")).map((f) => f.id)).toEqual(["theirs", "mine"]);
});

it("saves nothing for a subject whose factors the decision leaves as they are", async () => {
	const { factors } = memoryFactors();
	const refusing: FactorStore = { ...factors, save: () => Promise.reject(new Error("saved")) };
	expect(await factorRecords(refusing).decide("sam", () => ({ verdict: "kept" }))).toBe("kept");
	expect(await factorRecords(factors).list("sam")).toEqual([]);
});

it("answers unavailable when a list said to exist cannot be found", async () => {
	const { factors } = memoryFactors();
	const lying: FactorStore = { ...factors, save: async () => "exists" };
	await expect(factorRecords(lying).decide("sam", added("mine"))).rejects.toSatisfy(isUnavailable);
});
