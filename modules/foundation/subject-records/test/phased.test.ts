import { randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type Control, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import {
	indexSpaceOf,
	phasedKeyedSetsIn,
	phasedRecordsIn,
	subjectRecordsPhase,
} from "../src/subject-records.ts";

const g = ["durable"] as const;
const keyed: Space = { name: "phased-keyed", guarantees: g, subjectData: "online-keyed" };
const held = contract<Store>("test.store");
const refuse = (where: string, reason: string): never => {
	throw new Error(`refused at build: ${where}: ${reason}`);
};

/** A store control that answers the phase given, or is down, counting its reads. */
function control(phase: "reader" | "indexed") {
	const state = { down: false, reads: 0 };
	const marks =
		phase === "indexed" ? { "subject-records.phase": { value: "indexed", epoch: "e" } } : {};
	return {
		state,
		control: {
			control: async (): Promise<Control> => {
				state.reads += 1;
				if (state.down) throw new Unavailable("store");
				return { epoch: "e", maintenance: false, requires: [], marks };
			},
		},
	};
}

async function opened() {
	const recorded = recordingLog();
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "user", replicaSafe: false, takes: [store] }, (m) => [
				m.contribute(spaces).by(() => keyed),
				m.contribute(spaces).by(() => indexSpaceOf(keyed)),
				m.provide(held).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const s = app.get(held);
	const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
	const place = (over: Store = s) => ({
		store: over,
		space: keyed,
		index: indexSpaceOf(keyed),
		random,
		log: recorded.log,
	});
	return { s, place, recorded };
}

it("holds the phase once read, reads again after a blip, and reads none without a control", async () => {
	const { state, control: c } = control("indexed");
	const phase = subjectRecordsPhase.once(c);
	state.down = true;
	await expect(phase.read()).rejects.toThrow(Unavailable);
	await expect(phase.read()).rejects.toThrow(Unavailable);
	state.down = false;
	expect(await phase.read()).toBe("indexed");
	expect(await phase.read()).toBe("indexed");
	expect(state.reads).toBe(3);
	expect(await subjectRecordsPhase.once(undefined).read()).toBe("reader");
});

it("starts over a store's blip, unready and unavailable until the phase reads, then routes every call through it", async () => {
	const { place } = await opened();
	const { state, control: c } = control("indexed");
	state.down = true;
	const records = await phasedRecordsIn<number>(place(), subjectRecordsPhase.once(c), "w", refuse);
	await expect(records.ready()).rejects.toThrow(Unavailable);
	await expect(records.create("alice", 1, "endless", "alice")).rejects.toThrow(Unavailable);
	state.down = false;
	await records.ready();
	expect(await records.create("alice", 1, "endless", "alice")).toBe("created");
	expect(await records.change("alice", (n) => ({ value: n + 1 }))).toEqual({ before: 1, after: 2 });
	expect(await records.read("alice")).toBe(2);
	expect((await records.scan()).keys).toEqual(["alice"]);
	await expect(records.move("alice", "alice", "bob")).rejects.toThrow();
	await records.remove("alice");
	expect(await records.read("alice")).toBeUndefined();
	const sets = await phasedKeyedSetsIn(
		{ ...place(), cap: 5, clock: { now: () => Date.now() } },
		subjectRecordsPhase.once(c),
		"w",
		refuse,
	);
	await sets.ready();
	expect(await sets.add("bob", "m", 60_000, "bob")).toEqual({ pushedOut: [] });
	expect((await sets.members("bob")).map((m) => m.member)).toEqual(["m"]);
});

it("refuses at build where the phase reads then, and where found late keeps readiness failing with why, judging no call", async () => {
	const { s, place, recorded } = await opened();
	const { batchAcross: _, ...lacking } = s;
	const unpaired = place(lacking as Store);
	const { state, control: c } = control("indexed");
	await expect(phasedRecordsIn(unpaired, subjectRecordsPhase.once(c), "w", refuse)).rejects.toThrow(
		"refused at build",
	);
	state.down = true;
	const records = await phasedRecordsIn<number>(unpaired, subjectRecordsPhase.once(c), "w", refuse);
	state.down = false;
	await expect(records.ready()).rejects.toThrow(
		"w: its store writes no records of two partitions as one",
	);
	await expect(records.create("alice", 1, "endless", "alice")).rejects.toThrow(Unavailable);
	await expect(records.ready()).rejects.toThrow("two partitions");
	expect(recorded.lines().filter((l) => l.event === "subject-records.refused")).toHaveLength(1);
});

it("erases and migrates the space at the phase read, unavailable until it reads, so the wiring never handles it", async () => {
	const { place } = await opened();
	const { state, control: c } = control("indexed");
	state.down = true;
	const records = await phasedRecordsIn<number>(place(), subjectRecordsPhase.once(c), "w", refuse);
	const signal = new AbortController().signal;
	await expect(records.erase("alice", signal)).rejects.toThrow(Unavailable);
	state.down = false;
	expect(await records.create("alice", 1, "endless", "alice")).toBe("created");
	expect(await records.erase("alice", signal)).toMatchObject({ kind: "erased", removed: 1 });
	expect(await records.create("alice", 2, "endless", "alice")).toBe("erased");
	const walk = { sweep: async () => ({ keys: [], server: "one" }) };
	expect(await records.migrate(walk, async () => ({ kind: "orphan" }), signal)).toMatchObject({
		kind: "migrated",
		indexed: 0,
		removed: 0,
	});
});
