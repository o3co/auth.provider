import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Alone, ErasureMaintenance } from "../../maintenance/maintenance.ts";
import { entryTimeMark, underKeyAndAlone } from "../step.ts";

const clock = { now: () => 1_000 };

/** A value thrown in place of an answer, whatever it is. */
const throwing = (thrown: unknown) => ({ thrown });
type Thrown = ReturnType<typeof throwing>;

/**
 * A stand-in answering `alone()` from `seen` in turn, recording every call the step makes. The record
 * shows the key held or not (`held`), with its epoch (`epoch`, e1 where held, none where not by
 * default); `recording`, `entering` and `marking` are thrown by `record()`, `enter()` and `mark()`
 * where given.
 */
function standIn(
	seen: (Alone | Error | Thrown)[],
	options: {
		readonly held?: boolean;
		readonly epoch?: string | null;
		readonly recording?: unknown;
		readonly entering?: Error;
		readonly marking?: Error;
	} = {},
) {
	const calls: string[] = [];
	const marks: [string, unknown][] = [];
	let held = options.held ?? true;
	let epoch = options.epoch === undefined ? (held ? "e1" : null) : options.epoch;
	const maintenance = {
		record: async () => {
			calls.push("record");
			if (options.recording !== undefined) throw options.recording;
			return { epoch, maintenance: held, requires: [], marks: {} };
		},
		enter: async () => {
			calls.push("enter");
			if (options.entering) throw options.entering;
			held = true;
			epoch = "e2";
			return { kind: "entered" as const, epoch };
		},
		mark: async (name: string, value: unknown) => {
			calls.push("mark");
			if (options.marking) throw options.marking;
			marks.push([name, value]);
			return { kind: "marked" as const };
		},
		alone: async () => {
			calls.push("alone");
			const next = seen.shift();
			if (next === undefined) throw new Error("alone() asked once more than the case says");
			if (next instanceof Error) throw next;
			if ("thrown" in next) throw next.thrown;
			return next;
		},
	} as unknown as ErasureMaintenance;
	return { maintenance, calls, marks };
}

const alone: Alone = { kind: "alone" };
const accompanied: Alone = { kind: "accompanied", count: 2 };
const unchecked: Alone = { kind: "unchecked", reasons: ["replica-unreached"] };

describe("entering, erasure-enter's alone", () => {
	it("reads alone, enters, reads alone again, writes the entry time, and answers under the key with the new epoch", async () => {
		const { maintenance, calls, marks } = standIn([alone, alone], { held: false });
		expect(await underKeyAndAlone(maintenance, "entering", clock)).toEqual({
			kind: "under-key",
			epoch: "e2",
		});
		expect(calls).toEqual(["alone", "enter", "alone", "mark"]);
		expect(marks).toEqual([[entryTimeMark, 1_000]]);
	});

	it("refuses accompanied or unchecked at the first read without entering", async () => {
		for (const found of [accompanied, unchecked]) {
			const { maintenance, calls } = standIn([found], { held: false });
			expect(await underKeyAndAlone(maintenance, "entering", clock)).toEqual(found);
			expect(calls).toEqual(["alone"]);
		}
	});

	it("answers entered-not-shown-alone where the read after entering finds the store not alone, with what it found and the way on", async () => {
		const ways = [
			[accompanied, "stop that client and run erasure-enter again"],
			[unchecked, "run erasure-enter again once every server answers"],
		] as const;
		for (const [found, wayOn] of ways) {
			const { maintenance, calls, marks } = standIn([alone, found], { held: false });
			expect(await underKeyAndAlone(maintenance, "entering", clock)).toEqual({
				kind: "entered-not-shown-alone",
				epoch: "e2",
				found,
				wayOn,
			});
			expect(calls).toEqual(["alone", "enter", "alone"]);
			expect(marks).toEqual([]);
		}
	});

	it("stops as unavailable where the first read is, before entering", async () => {
		const { maintenance, calls } = standIn([new Unavailable("store")], { held: false });
		await expect(underKeyAndAlone(maintenance, "entering", clock)).rejects.toBeInstanceOf(
			Unavailable,
		);
		expect(calls).toEqual(["alone"]);
	});

	it("stops as unavailable where enter() is, calling nothing after it", async () => {
		const { maintenance, calls } = standIn([alone], {
			held: false,
			entering: new Unavailable("store"),
		});
		await expect(underKeyAndAlone(maintenance, "entering", clock)).rejects.toBeInstanceOf(
			Unavailable,
		);
		expect(calls).toEqual(["alone", "enter"]);
	});

	it("answers entered-not-shown-alone, unavailable, where the read after entering gives no answer, as the key is set", async () => {
		const { maintenance, calls, marks } = standIn([alone, new Unavailable("store")], {
			held: false,
		});
		expect(await underKeyAndAlone(maintenance, "entering", clock)).toEqual({
			kind: "entered-not-shown-alone",
			epoch: "e2",
			found: { kind: "unavailable" },
			wayOn: "run erasure-enter again once every server answers",
		});
		expect(calls).toEqual(["alone", "enter", "alone"]);
		expect(marks).toEqual([]);
	});

	it("stops as unavailable where the entry-time mark is, calling nothing after it", async () => {
		const { maintenance, calls, marks } = standIn([alone, alone], {
			held: false,
			marking: new Unavailable("store"),
		});
		await expect(underKeyAndAlone(maintenance, "entering", clock)).rejects.toBeInstanceOf(
			Unavailable,
		);
		expect(calls).toEqual(["alone", "enter", "alone", "mark"]);
		expect(marks).toEqual([]);
	});

	it("throws any other failure of the read after entering as it is", async () => {
		const failure = new Error("not the store's outage");
		const { maintenance, calls } = standIn([alone, failure], { held: false });
		await expect(underKeyAndAlone(maintenance, "entering", clock)).rejects.toBe(failure);
		expect(calls).toEqual(["alone", "enter", "alone"]);
	});

	it("knows another copy of the kernel's outage after entering by its mark, not its class", async () => {
		const elsewhere = Object.assign(new Error("store unavailable"), {
			[Symbol.for("@mod/kernel.unavailable")]: true,
		});
		const { maintenance } = standIn([alone, elsewhere], { held: false });
		expect(await underKeyAndAlone(maintenance, "entering", clock)).toMatchObject({
			kind: "entered-not-shown-alone",
			found: { kind: "unavailable" },
		});
	});

	it("throws a thrown value that is no error, after entering, as it is", async () => {
		for (const thrown of ["a string", { plain: true }]) {
			const { maintenance, calls } = standIn([alone, throwing(thrown)], { held: false });
			await expect(underKeyAndAlone(maintenance, "entering", clock)).rejects.toBe(thrown);
			expect(calls).toEqual(["alone", "enter", "alone"]);
		}
	});
});

describe("passing, every other command's", () => {
	it("refuses not-in-maintenance where the key has lifted and the record still holds its epoch", async () => {
		const { maintenance, calls } = standIn([], { held: false, epoch: "e1" });
		expect(await underKeyAndAlone(maintenance, "passing", clock)).toEqual({
			kind: "not-in-maintenance",
		});
		expect(calls).toEqual(["record"]);
	});

	it("refuses not-in-maintenance where the record shows the key held with no epoch", async () => {
		const { maintenance, calls } = standIn([], { held: true, epoch: null });
		expect(await underKeyAndAlone(maintenance, "passing", clock)).toEqual({
			kind: "not-in-maintenance",
		});
		expect(calls).toEqual(["record"]);
	});

	it("stops as unavailable where record() is, reading nothing after it", async () => {
		const outage = new Unavailable("store");
		const { maintenance, calls } = standIn([], { recording: outage });
		await expect(underKeyAndAlone(maintenance, "passing", clock)).rejects.toBe(outage);
		expect(calls).toEqual(["record"]);
	});

	it("stops as unavailable where alone() is, the outage as thrown", async () => {
		const outage = new Unavailable("store");
		const { maintenance, calls } = standIn([outage]);
		await expect(underKeyAndAlone(maintenance, "passing", clock)).rejects.toBe(outage);
		expect(calls).toEqual(["record", "alone"]);
	});

	it("answers under the key with the epoch read at record() where the key is held and the store alone, never entering or marking", async () => {
		const { maintenance, calls, marks } = standIn([alone]);
		expect(await underKeyAndAlone(maintenance, "passing", clock)).toEqual({
			kind: "under-key",
			epoch: "e1",
		});
		expect(calls).toEqual(["record", "alone"]);
		expect(marks).toEqual([]);
	});

	it("refuses not-in-maintenance where the key is not held, before reading alone", async () => {
		const { maintenance, calls } = standIn([], { held: false });
		expect(await underKeyAndAlone(maintenance, "passing", clock)).toEqual({
			kind: "not-in-maintenance",
		});
		expect(calls).toEqual(["record"]);
	});

	it("refuses accompanied or unchecked under the key, never entering", async () => {
		for (const found of [accompanied, unchecked]) {
			const { maintenance, calls } = standIn([found]);
			expect(await underKeyAndAlone(maintenance, "passing", clock)).toEqual(found);
			expect(calls).toEqual(["record", "alone"]);
		}
	});
});
