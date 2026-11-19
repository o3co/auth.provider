import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Alone, ErasureMaintenance } from "../../maintenance/maintenance.ts";
import { underKeyAndAlone } from "../step.ts";

/** A stand-in answering `alone()` from `seen` in turn, recording every call the step makes. */
function standIn(seen: (Alone | Error)[], held = true, entering?: Error) {
	const calls: string[] = [];
	let epoch: string | null = held ? "e1" : null;
	const maintenance = {
		record: async () => {
			calls.push("record");
			return { epoch, maintenance: held, requires: [], marks: {} };
		},
		enter: async () => {
			calls.push("enter");
			if (entering) throw entering;
			held = true;
			epoch = "e2";
			return { kind: "entered" as const, epoch };
		},
		alone: async () => {
			calls.push("alone");
			const next = seen.shift();
			if (next === undefined) throw new Error("alone() asked once more than the case says");
			if (next instanceof Error) throw next;
			return next;
		},
	} as unknown as ErasureMaintenance;
	return { maintenance, calls };
}

const alone: Alone = { kind: "alone" };
const accompanied: Alone = { kind: "accompanied", count: 2 };
const unchecked: Alone = { kind: "unchecked", reasons: ["replica-unreached"] };

describe("entering, erasure-enter's alone", () => {
	it("reads alone, enters, reads alone again, and answers under the key with the new epoch", async () => {
		const { maintenance, calls } = standIn([alone, alone], false);
		expect(await underKeyAndAlone(maintenance, "entering")).toEqual({
			kind: "under-key",
			epoch: "e2",
		});
		expect(calls).toEqual(["alone", "enter", "alone"]);
	});

	it("refuses accompanied or unchecked at the first read without entering", async () => {
		for (const found of [accompanied, unchecked]) {
			const { maintenance, calls } = standIn([found], false);
			expect(await underKeyAndAlone(maintenance, "entering")).toEqual(found);
			expect(calls).toEqual(["alone"]);
		}
	});

	it("answers entered-not-shown-alone where the read after entering finds the store not alone, with what it found and the way on", async () => {
		const ways = [
			[accompanied, "stop that client and run erasure-enter again"],
			[unchecked, "run erasure-enter again once every server answers"],
		] as const;
		for (const [found, wayOn] of ways) {
			const { maintenance, calls } = standIn([alone, found], false);
			expect(await underKeyAndAlone(maintenance, "entering")).toEqual({
				kind: "entered-not-shown-alone",
				epoch: "e2",
				found,
				wayOn,
			});
			expect(calls).toEqual(["alone", "enter", "alone"]);
		}
	});

	it("stops as unavailable where the first read is, before entering", async () => {
		const { maintenance, calls } = standIn([new Unavailable("store")], false);
		await expect(underKeyAndAlone(maintenance, "entering")).rejects.toBeInstanceOf(Unavailable);
		expect(calls).toEqual(["alone"]);
	});

	it("stops as unavailable where enter() is, calling nothing after it", async () => {
		const { maintenance, calls } = standIn([alone], false, new Unavailable("store"));
		await expect(underKeyAndAlone(maintenance, "entering")).rejects.toBeInstanceOf(Unavailable);
		expect(calls).toEqual(["alone", "enter"]);
	});

	it("answers entered-not-shown-alone, unavailable, where the read after entering gives no answer, as the key is set", async () => {
		const { maintenance, calls } = standIn([alone, new Unavailable("store")], false);
		expect(await underKeyAndAlone(maintenance, "entering")).toEqual({
			kind: "entered-not-shown-alone",
			epoch: "e2",
			found: { kind: "unavailable" },
			wayOn: "run erasure-enter again once every server answers",
		});
		expect(calls).toEqual(["alone", "enter", "alone"]);
	});

	it("throws any other failure of the read after entering as it is", async () => {
		const failure = new Error("not the store's outage");
		const { maintenance } = standIn([alone, failure], false);
		await expect(underKeyAndAlone(maintenance, "entering")).rejects.toBe(failure);
	});
});

describe("passing, every other command's", () => {
	it("answers under the key with the record's epoch where the key is held and the store alone, never entering", async () => {
		const { maintenance, calls } = standIn([alone]);
		expect(await underKeyAndAlone(maintenance, "passing")).toEqual({
			kind: "under-key",
			epoch: "e1",
		});
		expect(calls).toEqual(["record", "alone"]);
	});

	it("refuses not-in-maintenance where the key is not held, before reading alone", async () => {
		const { maintenance, calls } = standIn([], false);
		expect(await underKeyAndAlone(maintenance, "passing")).toEqual({ kind: "not-in-maintenance" });
		expect(calls).toEqual(["record"]);
	});

	it("refuses accompanied or unchecked under the key, never entering", async () => {
		for (const found of [accompanied, unchecked]) {
			const { maintenance, calls } = standIn([found]);
			expect(await underKeyAndAlone(maintenance, "passing")).toEqual(found);
			expect(calls).toEqual(["record", "alone"]);
		}
	});
});
