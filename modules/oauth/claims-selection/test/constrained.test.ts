import { Unavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { describe, expect, it } from "vitest";
import type { Selection, SelectionMode, Target } from "../src/contract.ts";
import { selectionsWith } from "../src/selections.ts";
import type { ConstrainedFamilyList, StoredSelection } from "../src/store.ts";

const constrained: Target = {
	names: [{ name: "name", scope: "profile" }],
	constraints: [{ name: "email", value: "a@example.com" }],
};
const named: Target = { names: [{ name: "name", scope: "profile" }], constraints: [] };
const none: Target = { names: [], constraints: [] };
const day = 86_400_000;

type Fault = ((name: string) => void | Promise<void>) | undefined;
type Memory = ReturnType<typeof memoryRecords<StoredSelection>>;
const clock = { now: 1_000_000 };

/** claims-selection's parts over records and a list in memory (another host's, where given), each of which a test may fail. */
function parts(
	mode: SelectionMode = "on",
	size = { shards: 4, perShard: 100 },
	memory: Memory = memoryRecords<StoredSelection>(() => clock.now, size),
) {
	const faults = {
		save: undefined as Fault,
		read: undefined as Fault,
		add: undefined as Fault,
		/** Runs after an add takes effect, before it answers. */
		added: undefined as Fault,
		done: undefined as Fault,
		/** Whether `each` fails to read one shard. */
		shard: false,
	};
	const list: ConstrainedFamilyList = {
		add: async (id) => {
			await faults.add?.(id);
			await memory.deferred.add(id);
			await faults.added?.(id);
		},
		done: async (id) => {
			await faults.done?.(id);
			await memory.deferred.done(id);
		},
		each: async (handle) => {
			const { failed } = await memory.deferred.each(handle);
			return { failed: failed + (faults.shard ? 1 : 0) };
		},
	};
	const recorded = recordingLog();
	const made = selectionsWith({
		records: {
			save: async (name, value, ms) => {
				await faults.save?.(name);
				return memory.records.create(name, value, ms);
			},
			read: async (name) => {
				await faults.read?.(name);
				return memory.records.read(name);
			},
		},
		list,
		log: recorded.log,
		consent: undefined,
		scopes: undefined,
		mode,
		now: () => clock.now,
	});
	/** Keeps a code's selection with `userinfo` and pins it, as a redemption does. */
	const pinned = async (redemption: string, userinfo: Target) => {
		const selection: Selection = { idToken: none, userinfo };
		if (mode === "on") await made.selections.keepForCode(redemption, selection, 600_000);
		await made.hook.pin(redemption);
	};
	return {
		...made,
		faults,
		memory,
		pinned,
		logged: recorded.lines,
		listed: () => memory.pending(),
	};
}
const advance = (ms: number) => {
	clock.now += ms;
};

/** A point a run is held at until the test opens it: `arrived` once the run reached it. */
const gate = () => {
	let open = () => {};
	let arrive = () => {};
	const opened = new Promise<void>((resolve) => {
		open = resolve;
	});
	const arrived = new Promise<void>((resolve) => {
		arrive = resolve;
	});
	return {
		arrived,
		open: () => open(),
		reached: async () => {
			arrive();
			await opened;
		},
	};
};

const failing = () => {
	throw new Unavailable("test");
};

describe("the families whose selection holds constraints", () => {
	it("lists a family once its selection is written, and only one whose userinfo target holds constraints", async () => {
		const p = parts();
		const seen: boolean[] = [];
		p.faults.add = () => {
			seen.push(p.listed().length === 0);
		};
		await p.pinned("r-1", constrained);
		await p.selections.follow("r-1", "fam-1", day);
		await p.pinned("r-2", named);
		await p.selections.follow("r-2", "fam-2", day);
		await p.hook.pin("r-3");
		await p.selections.follow("r-3", "fam-3", day);
		expect(p.listed()).toEqual(["fam-1"]);
		expect(seen).toEqual([true]);
	});

	it("fails the family's start where its selection, or its listing, cannot be written, or the listing's answer is lost", async () => {
		const p = parts();
		await p.pinned("r-1", constrained);
		p.faults.save = (name) => {
			if (name.startsWith("f.")) failing();
		};
		await expect(p.selections.follow("r-1", "fam-1", day)).rejects.toThrow(Unavailable);
		expect(p.listed()).toEqual([]);
		p.faults.save = undefined;
		p.faults.add = failing;
		await expect(p.selections.follow("r-1", "fam-2", day)).rejects.toThrow(Unavailable);
		expect(p.listed()).toEqual([]);
		p.faults.add = undefined;
		p.faults.added = failing;
		await expect(p.selections.follow("r-1", "fam-3", day)).rejects.toThrow(Unavailable);
		// Listed, though the family never started: revoking it later only marks a family with no record.
		expect(p.listed()).toEqual(["fam-3"]);
	});

	it("fails a constrained family's start past a full list, and starts any other as before", async () => {
		const p = parts("on", { shards: 1, perShard: 1 });
		await p.pinned("r-1", constrained);
		await p.selections.follow("r-1", "fam-1", day);
		await expect(p.selections.follow("r-1", "fam-2", day)).rejects.toThrow(Unavailable);
		await p.pinned("r-2", named);
		await p.selections.follow("r-2", "fam-3", day);
		expect(p.listed()).toEqual(["fam-1"]);
	});

	it("hands each listed family to the caller and unlists it, unlisting without it one whose selection ran out", async () => {
		const p = parts();
		await p.pinned("r-1", constrained);
		await p.selections.follow("r-1", "fam-1", day);
		await p.selections.follow("r-1", "fam-short", 1000);
		advance(999);
		const early: string[] = [];
		expect(
			await p.selections.constrainedFamilies(async (id) => {
				early.push(id);
				throw new Error("not yet");
			}),
		).toMatchObject({ handled: 0, expired: 0, failed: { handles: 2 } });
		expect(early.sort()).toEqual(["fam-1", "fam-short"]);
		// At its lifetime exactly, the selection has run out.
		advance(1);
		const handed: string[] = [];
		expect(
			await p.selections.constrainedFamilies(async (id) => {
				handed.push(id);
			}),
		).toEqual({
			handled: 1,
			expired: 1,
			failed: { shards: 0, reads: 0, handles: 0, removals: 0 },
		});
		expect(handed).toEqual(["fam-1"]);
		expect(p.listed()).toEqual([]);
	});

	it("keeps and counts a family whose selection cannot be read, whose handling or unlisting fails, and a shard it cannot read; a second run finishes them", async () => {
		const p = parts();
		await p.pinned("r-1", constrained);
		for (const id of ["fam-read", "fam-handle", "fam-done"])
			await p.selections.follow("r-1", id, day);
		p.faults.read = (name) => {
			if (name === "f.fam-read") failing();
		};
		p.faults.done = (id) => {
			if (id === "fam-done") failing();
		};
		p.faults.shard = true;
		const handed: string[] = [];
		const first = await p.selections.constrainedFamilies(async (id) => {
			if (id === "fam-handle") throw new Error("not revoked");
			handed.push(id);
		});
		expect(first).toEqual({
			handled: 0,
			expired: 0,
			failed: { shards: 1, reads: 1, handles: 1, removals: 1 },
		});
		expect(p.listed().sort()).toEqual(["fam-done", "fam-handle", "fam-read"]);
		Object.assign(p.faults, { read: undefined, done: undefined, shard: false });
		const second = await p.selections.constrainedFamilies(async () => {});
		expect(second).toMatchObject({
			handled: 3,
			failed: { shards: 0, reads: 0, handles: 0, removals: 0 },
		});
		expect(p.listed()).toEqual([]);
	});

	it("sweeps out only the families whose selection ran out, a family listed meanwhile never among them, and warns of what it could not read", async () => {
		const p = parts();
		await p.pinned("r-1", constrained);
		await p.selections.follow("r-1", "fam-long", day);
		await p.selections.follow("r-1", "fam-short", 1000);
		advance(1000);
		// A sweep right after a family is listed finds its selection, so keeps the listing.
		p.faults.added = () => p.sweep();
		await p.selections.follow("r-1", "fam-meanwhile", day);
		p.faults.added = undefined;
		expect(p.listed().sort()).toEqual(["fam-long", "fam-meanwhile"]);
		p.faults.read = failing;
		await p.sweep();
		expect(p.listed().sort()).toEqual(["fam-long", "fam-meanwhile"]);
		expect(p.logged()).toContainEqual(
			expect.objectContaining({
				level: "warn",
				event: "claims-selection.sweep_failed",
				fields: { count: 2 },
			}),
		);
	});

	it("never unlists a family listed while a sweep runs, nor one whose listing a whole sweep runs before", async () => {
		const p = parts();
		await p.pinned("r-1", constrained);
		await p.selections.follow("r-1", "fam-old", 1000);
		advance(1000);
		// The sweep held at the run-out family's selection, while another is founded and listed.
		const held = gate();
		p.faults.read = async (name) => {
			if (name === "f.fam-old") await held.reached();
		};
		const sweeping = p.sweep();
		await held.arrived;
		await p.selections.follow("r-1", "fam-new", day);
		held.open();
		await sweeping;
		p.faults.read = undefined;
		expect(p.listed()).toEqual(["fam-new"]);
		// A whole sweep between a family's selection and its listing finds it neither listed nor run out.
		p.faults.add = (id) => (id === "fam-late" ? p.sweep() : undefined);
		await p.selections.follow("r-1", "fam-late", day);
		p.faults.add = undefined;
		expect(p.listed().sort()).toEqual(["fam-late", "fam-new"]);
	});

	it("lists, hands and sweeps nothing when off, touching no store", async () => {
		const p = parts("off");
		Object.assign(p.faults, { save: failing, read: failing, add: failing, done: failing });
		await p.hook.pin("r-1");
		await p.selections.follow("r-1", "fam-1", day);
		expect(await p.selections.constrainedFamilies(failing)).toEqual({
			handled: 0,
			expired: 0,
			failed: { shards: 0, reads: 0, handles: 0, removals: 0 },
		});
		await p.sweep();
		expect(p.logged()).toEqual([]);
	});

	it("keeps listing the families it founds while draining, so one founded then is found", async () => {
		const on = parts();
		await on.pinned("r-1", constrained);
		const draining = parts("draining", undefined, on.memory);
		await draining.selections.follow("r-1", "fam-1", day);
		expect(draining.listed()).toEqual(["fam-1"]);
	});
});
