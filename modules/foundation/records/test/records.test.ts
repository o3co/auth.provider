import { randomBytes } from "node:crypto";
import { assemble, contract, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type Space, type Store, spaces, store } from "@mod/store";
import { type SimulatedStore, simulatedStore } from "@mod/store/testing";
import { expect, it, vi } from "vitest";
import {
	type Deferred,
	deferredIn,
	type KeyedSets,
	keyedSetsIn,
	type Records,
	recordsIn,
	secretRecordsIn,
} from "../src/records.ts";
import { shardOf } from "../src/shards.ts";
import { crowdingFor, memoryRecords } from "../src/testing.ts";

const runtime = quietRuntime({
	clock: { now: () => 1_800_000_000_000 },
	random: { bytes: (n) => new Uint8Array(n) },
});
const space: Space = { name: "records-test", guarantees: ["no-eviction", "durable", "replicated"] };
const opened = contract<Store>("test.store");

async function open() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "user" }, (m) => [
				m.contribute(spaces).by(() => space),
				m.provide(opened).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
	const recorded = recordingLog();
	/** The events of the warn and error lines so far. */
	const logged = () =>
		recorded
			.lines()
			.filter((line) => line.level !== "info")
			.map((line) => line.event);
	const place = { store: app.get(opened), space, random, log: recorded.log };
	return {
		simulated,
		logged,
		place,
		records: recordsIn<Counted>(place),
		deferred: deferredIn({ ...place, ...size }),
	};
}

/** A small size for deferred work, so a shard fills quickly. */
const size = { shards: 8, perShard: 6 };
const crowding = crowdingFor(size);

type Counted = { readonly n: number };

/** The jobs `each` hands over, sorted. */
async function listedIn(deferred: Deferred): Promise<string[]> {
	const listed: string[] = [];
	await deferred.each(async (job) => void listed.push(job));
	return listed.sort();
}

/** Another request's write applies on the primary, but its confirmation never comes. */
async function unconfirmed(simulated: SimulatedStore, write: () => Promise<unknown>) {
	simulated.stallReplicas(true);
	await expect(write()).rejects.toThrow();
	simulated.stallReplicas(false);
}

it("creates a record once, changes it from what it holds, and keeps it when the change says nothing", async () => {
	const { records } = await open();
	expect(await records.create("a", { n: 1 }, 60_000)).toBe("created");
	expect(await records.create("a", { n: 9 }, 60_000)).toBe("exists");
	expect(await records.change("a", (r) => ({ value: { n: r.n + 1 } }))).toEqual({
		before: { n: 1 },
		after: { n: 2 },
	});
	expect(await records.change("a", () => undefined)).toEqual({ before: { n: 2 }, after: { n: 2 } });
	expect(await records.change("none", (r) => ({ value: r }))).toBeUndefined();
});

it("runs a change again on what another writer left, and never on a record gone", async () => {
	const { simulated, records } = await open();
	await records.create("b", { n: 1 }, 60_000);
	const seen: number[] = [];
	simulated.beforeNext("replaceIf", space.name, async () => {
		await records.change("b", (r) => ({ value: { n: r.n * 10 } }));
	});
	const after = await records.change("b", (r) => {
		seen.push(r.n);
		return { value: { n: r.n + 1 } };
	});
	expect(seen).toEqual([1, 10]);
	expect(after?.after).toEqual({ n: 11 });
});

it("settles a create and a change whose answers were lost, so each takes effect once", async () => {
	const { simulated, records } = await open();
	simulated.loseNextReply();
	expect(await records.create("lost", { n: 1 }, 60_000)).toBe("created");
	let runs = 0;
	simulated.loseNextReply();
	const after = await records.change("lost", (r) => {
		runs++;
		return { value: { n: r.n + 1 } };
	});
	expect([runs, after]).toEqual([1, { before: { n: 1 }, after: { n: 2 } }]);
	expect(await records.change("lost", () => undefined)).toEqual({
		before: { n: 2 },
		after: { n: 2 },
	});
});

it("refuses a create that reaches the store after its deadline, and leaves no record", async () => {
	const { simulated, records } = await open();
	simulated.beforeNext("putIfAbsent", space.name, async () => simulated.shiftClock(11_000));
	await expect(records.create("late", { n: 1 }, 60_000)).rejects.toSatisfy(isUnavailable);
	expect(await records.change("late", (r) => ({ value: r }))).toBeUndefined();
});

it("refuses a change that reaches the store after its deadline, and keeps what the record held", async () => {
	const { simulated, records } = await open();
	await records.create("slow", { n: 1 }, 60_000);
	simulated.beforeNext("replaceIf", space.name, async () => simulated.shiftClock(11_000));
	await expect(records.change("slow", (r) => ({ value: { n: r.n + 1 } }))).rejects.toSatisfy(
		isUnavailable,
	);
	expect(await records.change("slow", () => undefined)).toEqual({
		before: { n: 1 },
		after: { n: 1 },
	});
});

it("answers nothing for a change whose record is removed meanwhile", async () => {
	const { simulated, place, records } = await open();
	await records.create("gone", { n: 1 }, 60_000);
	simulated.beforeNext("replaceIf", space.name, async () => {
		await place.store.take({ space, partition: "gone", name: "record" });
	});
	expect(await records.change("gone", (r) => ({ value: { n: r.n + 1 } }))).toBeUndefined();
});

it("reads a record while it lives, and none past its lifetime", async () => {
	const { simulated, records } = await open();
	await records.create("r", { n: 1 }, 1000);
	expect(await records.read("r")).toEqual({ n: 1 });
	expect(await records.read("none")).toBeUndefined();
	simulated.shiftClock(1000);
	expect(await records.read("r")).toBeUndefined();
});

it("removes a record whatever it holds, through a lost answer, and a record already gone", async () => {
	const { simulated, records } = await open();
	await records.create("r", { n: 1 }, 60_000);
	simulated.loseNextReply();
	await records.remove("r");
	expect(await records.read("r")).toBeUndefined();
	await records.remove("r");
});

it("refuses a removal that reaches the store after its deadline, and keeps the record", async () => {
	const { simulated, records } = await open();
	await records.create("kept", { n: 1 }, 60_000);
	simulated.beforeNext("take", space.name, async () => simulated.shiftClock(11_000));
	await expect(records.remove("kept")).rejects.toSatisfy(isUnavailable);
	expect(await records.read("kept")).toEqual({ n: 1 });
});

it("removes a record for good when the answer to its removal was lost and the store then fails over", async () => {
	const { simulated, records } = await open();
	await records.create("gone", { n: 1 }, 60_000);
	simulated.loseNextReply();
	await records.remove("gone");
	await simulated.failover();
	expect(await records.read("gone")).toBeUndefined();
});

it("gives up on a store that never answers once its pauses add up, as unavailable", async () => {
	const { simulated, records } = await open();
	await records.create("silent", { n: 1 }, 60_000);
	vi.useFakeTimers({ toFake: ["setTimeout"] });
	try {
		simulated.failWrites(true);
		const changed = records.change("silent", (r) => ({ value: { n: r.n + 1 } })).catch((e) => e);
		const created = records.create("never", { n: 1 }, 60_000).catch((e) => e);
		await vi.advanceTimersByTimeAsync(9_000);
		let settled = false;
		void Promise.all([changed, created]).then(() => {
			settled = true;
		});
		await vi.advanceTimersByTimeAsync(0);
		expect(settled).toBe(false);
		await vi.advanceTimersByTimeAsync(2_000);
		expect(isUnavailable(await changed)).toBe(true);
		expect(isUnavailable(await created)).toBe(true);
	} finally {
		simulated.failWrites(false);
		vi.useRealTimers();
	}
	expect(await records.change("silent", () => undefined)).toEqual({
		before: { n: 1 },
		after: { n: 1 },
	});
});

it("lets the store end a record when its lifetime runs out", async () => {
	const { simulated, records } = await open();
	await records.create("c", { n: 1 }, 1000);
	await records.change("c", (r) => ({ value: r, lifetimeMs: 5000 }));
	simulated.shiftClock(4000);
	expect(await records.change("c", () => undefined)).toBeDefined();
	simulated.shiftClock(2000);
	expect(await records.change("c", () => undefined)).toBeUndefined();
});

/** A record made or changed to live without end outlives any clock, through the store's sweeps of what ended. */
async function endlessOutlivesTheClock(records: Records<Counted>, advance: (ms: number) => void) {
	await records.create("endless", { n: 1 }, 1000);
	await records.create("ending", { n: 1 }, 1000);
	await records.create("born-endless", { n: 2 }, "endless");
	await records.change("endless", (r) => ({ value: r, lifetimeMs: "endless" }));
	advance(10 * 365 * 86_400_000);
	for (let i = 0; i < 300; i++) await records.create(`filler-${i}`, { n: i }, 1);
	expect(await records.read("endless")).toEqual({ n: 1 });
	expect(await records.read("ending")).toBeUndefined();
	expect(await records.read("born-endless")).toEqual({ n: 2 });
	await records.change("endless", (r) => ({ value: r, lifetimeMs: 1000 }));
	advance(1000);
	expect(await records.read("endless")).toBeUndefined();
}

it("keeps a record made or changed to live without end, however far the store clock runs", async () => {
	const { simulated, place } = await open();
	await endlessOutlivesTheClock(recordsIn<Counted>(place), (ms) => simulated.shiftClock(ms));
});

it("offers records in memory that keep a record without end as records' do", async () => {
	let now = 0;
	await endlessOutlivesTheClock(memoryRecords<Counted>(() => now, size).records, (ms) => {
		now += ms;
	});
});

it("keeps deferred work until it is done, and counts work whose handling failed", async () => {
	const { deferred } = await open();
	for (const job of ["j1", "j2", "j3"]) await deferred.add(job);
	const handled: string[] = [];
	const first = await deferred.each(async (job) => {
		handled.push(job);
		if (job === "j2") throw new Error("not yet");
		await deferred.done(job);
	});
	expect(handled.sort()).toEqual(["j1", "j2", "j3"]);
	expect(first).toEqual({ failed: 1 });
	const left: string[] = [];
	await deferred.each(async (job) => {
		left.push(job);
	});
	expect(left).toEqual(["j2"]);
});

it("refuses work past a full shard without losing any work it keeps", async () => {
	const { logged, deferred } = await open();
	const [over, ...kept] = crowding.jobs(size.perShard + 1);
	for (const job of kept) await deferred.add(job);
	await deferred.add(kept[0]);
	await expect(deferred.add(over)).rejects.toSatisfy(isUnavailable);
	expect(logged()).toEqual(["records.full"]);
	expect(await listedIn(deferred)).toEqual([...kept].sort());
	await deferred.done(kept[0]);
	await deferred.add(over);
}, 60_000);

it("keeps a job found full that another caller adds once room is made, without refusing it", async () => {
	const { simulated, logged, deferred } = await open();
	const [over, ...kept] = crowding.jobs(size.perShard + 1);
	for (const job of kept) await deferred.add(job);
	simulated.beforeNext("batch", space.name, async () => {
		await deferred.done(kept[0]);
		await deferred.add(over);
	});
	await deferred.add(over);
	expect(logged()).toEqual([]);
}, 60_000);

it("keeps both of two jobs whose first adds to an empty shard race, and goes on past an unreadable shard", async () => {
	const { simulated, deferred } = await open();
	const [first, second] = crowding.jobs(2);
	simulated.beforeNext("putIfAbsent", space.name, async () => {
		await deferred.add(second);
	});
	await deferred.add(first);
	simulated.failNext("get");
	const listed: string[] = [];
	const swept = await deferred.each(async (job) => {
		listed.push(job);
	});
	expect([swept.failed, listed.length]).toEqual([1, 0]);
	await deferred.each(async (job) => {
		listed.push(job);
	});
	expect(listed.sort()).toEqual([first, second].sort());
});

it("settles added and done work whose answers were lost, through a failover", async () => {
	const { simulated, deferred } = await open();
	simulated.loseNextReply();
	await deferred.add("kept");
	await deferred.add("finished");
	simulated.loseNextReply();
	await deferred.done("finished");
	await simulated.failover();
	expect(await listedIn(deferred)).toEqual(["kept"]);
});

it("offers jobs that crowd one shard, which the stand-in fills and refuses past as records does", async () => {
	const jobs = crowding.jobs(crowding.limit + 1);
	expect(new Set(jobs).size).toBe(crowding.limit + 1);
	const { deferred } = await open();
	const stand = memoryRecords<Counted>(() => 0, size);
	for (const job of jobs.slice(1)) {
		await deferred.add(job);
		await stand.deferred.add(job);
	}
	await stand.deferred.add(jobs[1]);
	await expect(deferred.add(jobs[0])).rejects.toSatisfy(isUnavailable);
	await expect(stand.deferred.add(jobs[0])).rejects.toSatisfy(isUnavailable);
	expect(stand.pending().sort()).toEqual(jobs.slice(1).sort());
	await deferred.add("elsewhere");
	await stand.deferred.add("elsewhere");
}, 60_000);

it("keeps deferred work in as many shards, and as much per shard, as the place is given", async () => {
	const given = { shards: 5, perShard: 3 };
	const crowd = crowdingFor(given);
	expect(crowd.limit).toBe(3);
	const jobs = crowd.jobs(4);
	const { place } = await open();
	const deferred = deferredIn({ ...place, ...given });
	const stand = memoryRecords<Counted>(() => 0, given);
	for (const job of jobs.slice(1)) {
		await deferred.add(job);
		await stand.deferred.add(job);
	}
	await expect(deferred.add(jobs[0])).rejects.toSatisfy(isUnavailable);
	await expect(stand.deferred.add(jobs[0])).rejects.toSatisfy(isUnavailable);
	const wideSize = { shards: 300, perShard: 3 };
	const wide = deferredIn({ ...(await open()).place, ...wideSize });
	// Jobs in shards past the default count, which a sweep of only those would miss.
	const far: string[] = [];
	for (let i = 0; far.length < 3; i++) {
		if (shardOf(`far-${i}`, wideSize) >= 256) {
			far.push(`far-${i}`);
		}
	}
	for (const job of far) await wide.add(job);
	expect(await listedIn(wide)).toEqual([...far].sort());
});

/** What keyed sets do with a cap of 2, on a clock the test moves. */
async function setsKeepTheirMembers(sets: KeyedSets, advance: (ms: number) => void) {
	expect((await sets.add("k", "b", 3000)).pushedOut).toEqual([]);
	expect((await sets.add("k", "a", 1000)).pushedOut).toEqual([]);
	expect((await sets.add("k", "a", 500)).pushedOut).toEqual([]);
	expect(await sets.members("k")).toEqual([
		{ member: "a", remainingMs: 1000 },
		{ member: "b", remainingMs: 3000 },
	]);
	expect((await sets.add("k", "c", 2000)).pushedOut).toEqual(["a"]);
	expect((await sets.add("k", "d", 100)).pushedOut).toEqual(["c"]);
	expect((await sets.members("k")).map((m) => m.member)).toEqual(["b", "d"]);
	expect(await sets.members("other")).toEqual([]);
	advance(2000);
	expect(await sets.members("k")).toEqual([{ member: "b", remainingMs: 1000 }]);
	await sets.remove("k", "b");
	await sets.remove("k", "absent");
	expect(await sets.members("k")).toEqual([]);
}

/** With a cap of 1, what an add pushes out awaits, in the same write, until settled or its end passes. */
async function pushedOutAwaits(sets: KeyedSets, advance: (ms: number) => void) {
	await sets.add("k", "first", 5000);
	expect((await sets.add("k", "second", 1000)).pushedOut).toEqual(["first"]);
	expect(await sets.awaiting("k")).toEqual(["first"]);
	expect((await sets.add("k", "third", 1000)).pushedOut).toEqual(["second"]);
	expect(await sets.awaiting("k")).toEqual(["first", "second"]);
	expect((await sets.members("k")).map((m) => m.member)).toEqual(["third"]);
	await sets.settled("k", "first");
	await sets.settled("k", "absent");
	expect(await sets.awaiting("k")).toEqual(["second"]);
	expect(await sets.awaiting("other")).toEqual([]);
	// Past its token's end a pushed-out member needs nothing more, and awaits no longer.
	advance(1000);
	expect(await sets.awaiting("k")).toEqual([]);
}

it("offers keyed sets in memory that keep their members as records' do", async () => {
	let now = 0;
	await setsKeepTheirMembers(memoryRecords<Counted>(() => now, size).keyedSets(2), (ms) => {
		now += ms;
	});
	await capOfOne(memoryRecords<Counted>(() => now, size).keyedSets(1));
	expect(() => memoryRecords<Counted>(() => now, size).keyedSets(0)).toThrow(TypeError);
	await pushedOutAwaits(memoryRecords<Counted>(() => now, size).keyedSets(1), (ms) => {
		now += ms;
	});
});

it("keeps what an add pushes out awaiting in the set's own write, until settled or ended", async () => {
	const { sets, advance } = await clocked(1);
	await pushedOutAwaits(sets, advance);
});

it("reads a set kept as a bare list of members, as it was kept before anything awaited", async () => {
	const { place, now, sets } = await clocked(2);
	await place.store.putIfAbsent(
		{ space, partition: "bare", name: "set" },
		[["kept", now() + 60_000]],
		{
			expiry: { kind: "after", ms: 60_000 },
		},
	);
	expect(await sets.members("bare")).toEqual([{ member: "kept", remainingMs: 60_000 }]);
	expect(await sets.awaiting("bare")).toEqual([]);
	await sets.add("bare", "next", 1000);
	expect((await sets.members("bare")).map((m) => m.member)).toEqual(["kept", "next"]);
});

/** With a cap of 1, each add keeps its own member and pushes out the one before. */
async function capOfOne(sets: KeyedSets) {
	expect((await sets.add("k", "late", 5000)).pushedOut).toEqual([]);
	expect((await sets.add("k", "early", 100)).pushedOut).toEqual(["late"]);
	expect((await sets.add("k", "early", 50)).pushedOut).toEqual([]);
	expect((await sets.members("k")).map((m) => m.member)).toEqual(["early"]);
}

/** Keyed sets on the kernel's clock, moved with the store's by `advance`. */
async function clocked(cap: number) {
	const opened = await open();
	let now = 1_800_000_000_000;
	const clock = { now: () => now };
	const advance = (ms: number) => {
		now += ms;
		opened.simulated.shiftClock(ms);
	};
	return { ...opened, advance, now: clock.now, sets: keyedSetsIn({ ...opened.place, cap, clock }) };
}

it("keeps members until the kernel's clock passes the end each was added with", async () => {
	const { sets, advance } = await clocked(2);
	await setsKeepTheirMembers(sets, advance);
});

it("keeps the member it adds under a cap of 1, and refuses a cap below 1", async () => {
	await capOfOne((await clocked(1)).sets);
	await expect(clocked(0)).rejects.toThrow(TypeError);
	await expect(clocked(1.5)).rejects.toThrow(TypeError);
});

it("ends a member when its lifetime from its add runs out, however late a later write lands", async () => {
	const { simulated, sets, advance } = await clocked(3);
	await sets.add("k", "b", 3000);
	await sets.add("k", "old", 1000);
	simulated.beforeNext("replaceIf", space.name, async () => advance(1500));
	// Its end is its add's time plus its lifetime, whenever the write lands.
	expect((await sets.add("k", "new", 2000)).pushedOut).toEqual([]);
	expect(await sets.members("k")).toEqual([
		{ member: "b", remainingMs: 1500 },
		{ member: "new", remainingMs: 500 },
	]);
});

it("keeps a set in the store past its last member's end by a margin, for clearing up alone", async () => {
	const { place, sets, advance } = await clocked(2);
	await sets.add("k", "a", 1000);
	const kept = async () =>
		(await place.store.get({ space, partition: "k", name: "set" })).entry ?? undefined;
	advance(1000 + 9 * 60_000);
	expect([await sets.members("k"), (await kept()) !== undefined]).toEqual([[], true]);
	advance(2 * 60_000);
	expect(await kept()).toBeUndefined();
});

it("reads a kept set for what it is, holding no member from anything else in it", async () => {
	const { place, now, sets } = await clocked(4);
	const odd = [["kept", now() + 60_000], "loose", [1, 0], ["half"], { member: "x" }];
	await place.store.putIfAbsent({ space, partition: "odd", name: "set" }, odd, {
		expiry: { kind: "after", ms: 60_000 },
	});
	expect(await sets.members("odd")).toEqual([{ member: "kept", remainingMs: 60_000 }]);
});

it("evicts the first in code point order among the other members that end together", async () => {
	const { sets } = await clocked(2);
	await sets.add("k", "c", 1000);
	await sets.add("k", "b", 1000);
	expect((await sets.add("k", "a", 2000)).pushedOut).toEqual(["b"]);
});

it("settles an add and a removal whose answers were lost, with the first answer, through a failover", async () => {
	const { simulated, sets } = await clocked(1);
	await sets.add("k", "kept", 60_000);
	simulated.loseNextReply();
	expect((await sets.add("k", "new", 120_000)).pushedOut).toEqual(["kept"]);
	expect((await sets.add("k", "gone", 1000)).pushedOut).toEqual(["new"]);
	simulated.loseNextReply();
	await sets.remove("k", "gone");
	await simulated.failover();
	expect(await sets.members("k")).toEqual([]);
});

it("offers a memory stand-in that answers as records do and races a change", async () => {
	let now = 0;
	const stand = memoryRecords<Counted>(() => now, size);
	expect(await stand.records.create("a", { n: 1 }, 1000)).toBe("created");
	expect(await stand.records.create("a", { n: 2 }, 1000)).toBe("exists");
	stand.raceNextChange((r) => ({ n: r.n * 10 }));
	const seen: number[] = [];
	const after = await stand.records.change("a", (r) => {
		seen.push(r.n);
		return { value: { n: r.n + 1 } };
	});
	expect([seen, after?.after]).toEqual([[1, 10], { n: 11 }]);
	expect(await stand.records.read("a")).toEqual({ n: 11 });
	await stand.records.remove("a");
	expect(await stand.records.read("a")).toBeUndefined();
	await stand.records.create("a", { n: 10 }, 1000);
	now = 1000;
	expect(await stand.records.read("a")).toBeUndefined();
	expect(stand.peek("a")).toBeUndefined();
	await stand.deferred.add("j");
	expect(stand.pending()).toEqual(["j"]);
	expect(await stand.deferred.each(async () => Promise.reject(new Error("later")))).toEqual({
		failed: 1,
	});
	await stand.deferred.done("j");
	expect(stand.pending()).toEqual([]);
});

it("never takes another's unconfirmed removal for its own: a record it removes stays removed through a failover", async () => {
	const { simulated, place, records } = await open();
	await records.create("gone", { n: 1 }, 60_000);
	await unconfirmed(simulated, () =>
		place.store.take({ space, partition: "gone", name: "record" }, {}),
	);
	await records.remove("gone");
	await simulated.failover();
	expect(await records.read("gone")).toBeUndefined();
});

it("never answers removed while the record can come back: a failover after it finds none is met", async () => {
	const { simulated, place, records } = await open();
	await records.create("back", { n: 1 }, 60_000);
	await unconfirmed(simulated, () =>
		place.store.take({ space, partition: "back", name: "record" }, {}),
	);
	// The store fails over after the removal finds no record, before it writes anything more.
	for (const operation of ["put", "batch"] as const) {
		simulated.beforeNext(operation, space.name, () => simulated.failover());
	}
	await records.remove("back");
	expect(await records.read("back")).toBeUndefined();
	await simulated.failover();
	expect(await records.read("back")).toBeUndefined();
});

/** The place with one store operation answered as `answer` says once, then as the store answers. */
function once(
	place: Awaited<ReturnType<typeof open>>["place"],
	op: keyof Store,
	answer: () => unknown,
) {
	let calls = 0;
	let used = false;
	const store = new Proxy(place.store, {
		get: (target, name) => {
			const real = Reflect.get(target, name) as (...args: unknown[]) => unknown;
			if (name !== op) return real.bind(target);
			return (...args: unknown[]) => {
				calls++;
				if (used) return real.apply(target, args);
				used = true;
				return answer();
			};
		},
	});
	return { place: { ...place, store }, calls: () => calls };
}

it("resends only while the store is unavailable, and throws any other error at once", async () => {
	const { place } = await open();
	const faulty = once(place, "putIfAbsent", () => Promise.reject(new TypeError("a fault")));
	await expect(recordsIn<Counted>(faulty.place).create("a", { n: 1 }, 60_000)).rejects.toThrow(
		TypeError,
	);
	expect(faulty.calls()).toBe(1);
});

it("answers unavailable when the store says the write's mark was used by another write", async () => {
	const { place } = await open();
	await recordsIn<Counted>(place).create("a", { n: 1 }, 60_000);
	const reused = once(place, "replaceIf", async () => ({ kind: "reused" }));
	await expect(
		recordsIn<Counted>(reused.place).change("a", () => ({ value: { n: 2 } })),
	).rejects.toSatisfy(isUnavailable);
});

it("keeps a changed record's lifetime unless the change gives one, and gives at least 1 ms", async () => {
	const { simulated, records } = await open();
	await records.create("kept", { n: 1 }, 60_000);
	await records.change("kept", () => ({ value: { n: 2 } }));
	await records.create("short", { n: 1 }, 60_000);
	await records.change("short", () => ({ value: { n: 2 }, lifetimeMs: 0 }));
	expect(await records.read("short")).toEqual({ n: 2 });
	simulated.shiftClock(1);
	expect(await records.read("short")).toBeUndefined();
	simulated.shiftClock(59_998);
	expect(await records.read("kept")).toEqual({ n: 2 });
	simulated.shiftClock(1);
	expect(await records.read("kept")).toBeUndefined();
});

it("offers crowding jobs only two or more at a time", () => {
	expect(() => crowding.jobs(1)).toThrow(RangeError);
	expect(crowding.jobs(2)).toHaveLength(2);
});

it("resends the write that confirms an absence under the mark it was first sent with", async () => {
	const { simulated, place } = await open();
	const marks: unknown[] = [];
	const store = new Proxy(place.store, {
		get: (target, name) =>
			name === "batch"
				? (...args: Parameters<Store["batch"]>) => {
						marks.push(args[2]?.idempotency);
						return target.batch(...args);
					}
				: Reflect.get(target, name),
	});
	simulated.beforeNext("batch", space.name, async () => simulated.loseNextReply());
	await recordsIn<Counted>({ ...place, store }).remove("never-there");
	expect(marks).toHaveLength(2);
	expect(marks[1]).toBe(marks[0]);
});

it("gives up a removal as unavailable while the record keeps coming back", async () => {
	const { simulated, place, records } = await open();
	const held = { space, partition: "contended", name: "record" };
	await records.create("contended", { n: 1 }, 60_000);
	// Others keep removing the record just before each removal looks, and placing it again after.
	const contend = (times: number) => {
		if (times === 0) return;
		simulated.beforeNext("take", space.name, async () => {
			await place.store.take(held, {});
			simulated.beforeNext("batch", space.name, async () => {
				await place.store.put(held, { n: 1 }, { expiry: { kind: "never" } });
				contend(times - 1);
			});
		});
	};
	// One race for each of records' 8 attempts.
	contend(8);
	await expect(records.remove("contended")).rejects.toSatisfy(isUnavailable);
});

it("never answers that a record exists until a failover would keep it", async () => {
	const { simulated, records } = await open();
	const seen: { answer?: string; kept?: Counted | undefined } = {};
	// Another request's create applies on the primary; before it is confirmed, this one finds it,
	// and the store fails over at once.
	simulated.beforeConfirm("putIfAbsent", space.name, async () => {
		seen.answer = await records.create("raced", { n: 2 }, 60_000);
		await simulated.failover();
		seen.kept = await records.read("raced");
	});
	await records.create("raced", { n: 1 }, 60_000).catch(() => undefined);
	expect(seen.answer).toBe("exists");
	expect(seen.kept).toEqual({ n: 1 });
});

it("creates its own record when the one it found is lost before it is confirmed", async () => {
	for (const at of ["get", "batch"] as const) {
		const { simulated, records } = await open();
		const seen: { answer?: string; kept?: Counted | undefined } = {};
		simulated.beforeConfirm("putIfAbsent", space.name, async () => {
			// The other request's record is lost to a failover just before this one reads, or confirms, it.
			simulated.beforeNext(at, space.name, () => simulated.failover());
			seen.answer = await records.create("lost", { n: 2 }, 60_000);
			seen.kept = await records.read("lost");
		});
		await records.create("lost", { n: 1 }, 60_000).catch(() => undefined);
		expect([seen.answer, seen.kept], at).toEqual(["created", { n: 2 }]);
	}
});

it("gives up a create as unavailable while the record it finds keeps changing", async () => {
	const { simulated, place, records } = await open();
	const held = { space, partition: "busy", name: "record" };
	await records.create("busy", { n: 1 }, 60_000);
	// Another request rewrites the record just before each confirmation, so the version read never holds.
	const contend = (times: number) => {
		if (times === 0) return;
		simulated.beforeNext("batch", space.name, async () => {
			await place.store.put(held, { n: times }, { expiry: { kind: "after", ms: 60_000 } });
			contend(times - 1);
		});
	};
	// One race for each of records' 8 attempts.
	contend(8);
	await expect(records.create("busy", { n: 9 }, 60_000)).rejects.toSatisfy(isUnavailable);
});

it("never answers a change it decided not to make with a state a failover would undo", async () => {
	for (const other of ["changes", "removes"] as const) {
		const { simulated, records } = await open();
		await records.create("held", { n: 1 }, 60_000);
		const seen: { answer?: unknown; kept?: Counted | undefined } = {};
		// Another request's change or removal applies; before it is confirmed, this change looks,
		// decides to write nothing, and the store fails over at once.
		simulated.beforeConfirm(other === "changes" ? "replaceIf" : "take", space.name, async () => {
			seen.answer = (await records.change("held", () => undefined))?.after;
			await simulated.failover();
			seen.kept = await records.read("held");
		});
		await (other === "changes"
			? records.change("held", () => ({ value: { n: 2 } }))
			: records.remove("held")
		).catch(() => undefined);
		expect(seen.answer, other).toEqual(seen.kept);
	}
});

it("never answers a member removed while the set it found gone could come back", async () => {
	const { simulated, sets, advance } = await clocked(4);
	await sets.add("k", "m", 3_600_000);
	const seen: { members?: readonly string[] } = {};
	// One request removes m, another adds n for 1 ms; neither is confirmed when the set ends (n's
	// end and the set's clearing time pass, m's does not), a third removal finds it gone, and the
	// store fails over.
	simulated.beforeConfirm("replaceIf", space.name, async () => {
		simulated.beforeConfirm("replaceIf", space.name, async () => {
			advance(1 + 10 * 60_000 + 1);
			await sets.remove("k", "m");
			await simulated.failover();
			seen.members = (await sets.members("k")).map((member) => member.member);
		});
		await sets.add("k", "n", 1).catch(() => undefined);
	});
	await sets.remove("k", "m").catch(() => undefined);
	expect(seen.members).not.toContain("m");
});

it("never takes another's unconfirmed add for its own: work it adds stays through a failover", async () => {
	const { simulated, place, deferred } = await open();
	const shard = { space, partition: `jobs-${shardOf("job", size)}`, name: "jobs" };
	await unconfirmed(simulated, () =>
		place.store.putIfAbsent(shard, ["job"], { expiry: { kind: "never" } }),
	);
	await deferred.add("job");
	await simulated.failover();
	expect(await listedIn(deferred)).toEqual(["job"]);
});

it("never cuts short a member it keeps by a write that lands late", async () => {
	const { simulated, sets, advance } = await clocked(4);
	await sets.add("late", "kept", 5000);
	simulated.beforeNext("replaceIf", space.name, async () => advance(500));
	await sets.add("late", "new", 1000);
	const kept = (await sets.members("late")).find((m) => m.member === "kept");
	expect(kept?.remainingMs).toBe(4500);
});

it("keeps records under a secret by a name the store receives instead, stable and per space", async () => {
	const { place } = await open();
	const sent: string[] = [];
	const store = new Proxy(place.store, {
		get: (target, name) => {
			const op = Reflect.get(target, name) as (...args: unknown[]) => unknown;
			return (...args: unknown[]) => {
				sent.push(JSON.stringify(args));
				return op.apply(target, args);
			};
		},
	});
	const records = secretRecordsIn<Counted>({ ...place, store });
	const secret = "secret-1";
	// Names are kept elsewhere (lists, other features' keys), so this one must never change.
	expect(records.nameOf(secret)).toBe("1.G3iVzOKtlbB3EtxVynMcu47G2SieN4uADLJvnF2jB9Q");
	const elsewhere = { ...space, name: "records-test.other" };
	expect(secretRecordsIn({ ...place, space: elsewhere }).nameOf(secret)).not.toBe(
		records.nameOf(secret),
	);
	expect(await records.create(secret, { n: 1 }, 60_000)).toBe("created");
	expect(await records.change(secret, (r) => ({ value: { n: r.n + 1 } }))).toEqual({
		before: { n: 1 },
		after: { n: 2 },
	});
	expect(await records.read(secret)).toEqual({ n: 2 });
	expect(await records.named.read(records.nameOf(secret))).toEqual({ n: 2 });
	await records.remove(secret);
	expect(await records.read(secret)).toBeUndefined();
	expect(sent.length).toBeGreaterThan(0);
	expect(sent.some((args) => args.includes(secret))).toBe(false);
});

it("looks up any string under a secret, empty or odd, and refuses none for its shape", async () => {
	const { place } = await open();
	const records = secretRecordsIn<Counted>(place);
	for (const secret of ["", " ", "\n", "\u{1F511}", "a".repeat(10_000)]) {
		expect(await records.read(secret)).toBeUndefined();
		expect(await records.create(secret, { n: secret.length }, 60_000)).toBe("created");
		expect(await records.read(secret)).toEqual({ n: secret.length });
		expect(records.nameOf(secret)).toMatch(/^1\.[A-Za-z0-9_-]{43}$/);
	}
});
