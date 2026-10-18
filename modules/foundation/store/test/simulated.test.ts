import { assemble, defineModule, kernelConfig, type Runtime } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { type Space, spaces, store } from "../src/contract.ts";
import { simulatedStore } from "../src/testing.ts";

const space: Space = { name: "simulated", guarantees: ["no-eviction", "durable", "replicated"] };
const key = (name: string) => ({ space, partition: "p", name });
const now = 1_800_000_000_000;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
});

const never = { expiry: { kind: "never" } } as const;
const at = (where: Space, name: string) => ({ space: where, partition: "p", name });
const fullyConfirmed: Space = {
	name: "confirmed",
	guarantees: ["no-eviction", "durable", "replicated", "confirmed-reads"],
};

/** A simulated store over the spaces given, on the test's clock unless another is given. */
async function open(declared: readonly Space[] = [space], clock: Runtime["clock"] = runtime.clock) {
	const simulated = simulatedStore();
	const caller = defineModule({ name: "caller" }, (m) =>
		declared.map((d) => m.contribute(spaces).by(() => d)),
	);
	const app = await assemble({
		modules: [simulated.module, caller],
		config: kernelConfig(),
		runtime: { ...runtime, clock },
	});
	return { simulated, s: app.get(store) };
}

it("loses on failover what was applied but not confirmed, and keeps what a later write confirmed", async () => {
	const { simulated, s } = await open();
	simulated.loseNextReply();
	await expect(s.put(key("a"), 1, never)).rejects.toThrow();
	expect((await s.get(key("a"))).entry?.value).toBe(1);
	await simulated.failover();
	expect((await s.get(key("a"))).entry).toBeNull();

	simulated.loseNextReply();
	await expect(s.put(key("b"), 1, never)).rejects.toThrow();
	expect((await s.put(key("c"), 1, never)).kind).toBe("written");
	await simulated.failover();
	expect((await s.get(key("b"))).entry?.value).toBe(1);
});

it("tells whether any write it took carried a text in a key or a value, even one since lost", async () => {
	const { simulated, s } = await open();
	await s.put(key("in-a-key"), { note: 'in "a" value' }, never);
	simulated.loseNextReply();
	await expect(s.put(key("lost"), 1, never)).rejects.toThrow();
	await simulated.failover();
	await s.get(key("only-read"));
	expect(["in-a-key", 'in "a" value', "lost"].map((text) => simulated.holds(text))).toEqual([
		true,
		true,
		true,
	]);
	expect(simulated.holds("only-read")).toBe(false);
});

it("refuses writes or everything on demand, and keeps a clock of its own", async () => {
	const { simulated, s } = await open();
	simulated.failWrites(true);
	await expect(s.put(key("a"), 1, never)).rejects.toThrow();
	expect((await s.get(key("a"))).entry).toBeNull();
	simulated.failWrites(false);
	simulated.unreachable(true);
	await expect(s.get(key("a"))).rejects.toThrow();
	simulated.unreachable(false);
	await s.put(key("a"), 1, { expiry: { kind: "after", ms: 1000 } });
	simulated.shiftClock(1001);
	expect((await s.get(key("a"))).entry).toBeNull();
});

it("stalls replicas: replicated writes and confirmed reads fail, other spaces answer", async () => {
	const plain: Space = { name: "plain", guarantees: [] };
	const confirmed: Space = { name: "confirmed", guarantees: ["replicated", "confirmed-reads"] };
	const { simulated, s } = await open([space, plain, confirmed]);
	simulated.stallReplicas(true);
	await expect(s.put(at(space, "a"), 1, never)).rejects.toThrow();
	expect((await s.put(at(plain, "a"), 1, never)).kind).toBe("written");
	await expect(s.get(at(confirmed, "a"))).rejects.toThrow();
	expect((await s.get(at(space, "a"))).entry?.value).toBe(1);
	simulated.stallReplicas(false);
	await simulated.failover();
	expect((await s.get(at(space, "a"))).entry).toBeNull();
});

it("runs another client's write just before the next call of one operation on one space, once", async () => {
	const { simulated, s } = await open();
	const written = await s.put(key("a"), 1, never);
	const version = written.kind === "written" ? written.version : undefined;
	let runs = 0;
	simulated.beforeNext("replaceIf", "simulated", async () => {
		runs++;
		await s.put(key("a"), 2, never);
	});
	simulated.beforeNext("replaceIf", "elsewhere", async () => {
		runs += 10;
	});
	await s.get(key("a"));
	expect(runs).toBe(0);
	expect(
		(await s.replaceIf(key("a"), version as never, 3, { expiry: { kind: "keep" } })).kind,
	).not.toBe("written");
	expect((await s.get(key("a"))).entry?.value).toBe(2);
	const current = (await s.get(key("a"))).entry?.version;
	expect(
		(await s.replaceIf(key("a"), current as never, 3, { expiry: { kind: "keep" } })).kind,
	).toBe("written");
	expect(runs).toBe(1);
});

it("fails just the next call of one operation, without applying it", async () => {
	const { simulated, s } = await open();
	await s.put(key("a"), 1, never);
	simulated.failNext("removeIf");
	await expect(s.removeIf(key("a"), { value: 1 })).rejects.toThrow();
	expect((await s.get(key("a"))).entry?.value).toBe(1);
	await s.put(key("b"), 2, never);
	expect((await s.removeIf(key("a"), { value: 1 })).kind).toBe("removed");
});

/** A store with one space that holds every guarantee and one for each guarantee it lacks. */
async function openWith() {
	const all: Space = space;
	const lacking = {
		replicated: { name: "unreplicated", guarantees: ["no-eviction", "durable"] },
		durable: { name: "volatile", guarantees: ["no-eviction", "replicated"] },
		"no-eviction": { name: "evictable", guarantees: ["durable", "replicated"] },
	} as const satisfies Record<string, Space>;
	const { simulated, s } = await open([all, ...Object.values(lacking)]);
	return { simulated, s, all, lacking };
}

it("confirms a write in a space without replication only when a replicated write follows it", async () => {
	const { simulated, s, all, lacking } = await openWith();
	await s.put(at(lacking.replicated, "a"), 1, never);
	await simulated.failover();
	expect((await s.get(at(lacking.replicated, "a"))).entry).toBeNull();
	await s.put(at(lacking.replicated, "b"), 1, never);
	await s.put(at(all, "c"), 1, never);
	await simulated.failover();
	expect((await s.get(at(lacking.replicated, "b"))).entry?.value).toBe(1);
});

it("loses spaces that are not durable on a restart, and keeps the durable ones", async () => {
	const { simulated, s, all, lacking } = await openWith();
	await s.put(at(lacking.durable, "a"), 1, never);
	await s.put(at(all, "b"), 1, never);
	await simulated.restart();
	expect((await s.get(at(lacking.durable, "a"))).entry).toBeNull();
	expect((await s.get(at(all, "b"))).entry?.value).toBe(1);
	await simulated.failover();
	expect((await s.get(at(all, "b"))).entry?.value).toBe(1);
});

it("clears spaces not kept from eviction under memory pressure, and keeps the others", async () => {
	const { simulated, s, all, lacking } = await openWith();
	await s.put(at(lacking["no-eviction"], "a"), 1, never);
	await s.put(at(all, "b"), 1, never);
	await simulated.pressMemory();
	expect((await s.get(at(lacking["no-eviction"], "a"))).entry).toBeNull();
	expect((await s.get(at(all, "b"))).entry?.value).toBe(1);
	await simulated.failover();
	expect((await s.get(at(lacking["no-eviction"], "a"))).entry).toBeNull();
	expect((await s.get(at(all, "b"))).entry?.value).toBe(1);
});

it("confirms what a confirmed read answers and what a refusal in such a space saw, so a failover keeps both", async () => {
	const { simulated, s } = await open([fullyConfirmed]);
	simulated.loseNextReply();
	await expect(s.put(at(fullyConfirmed, "read"), 1, never)).rejects.toThrow();
	expect((await s.get(at(fullyConfirmed, "read"))).entry?.value).toBe(1);
	await simulated.failover();
	expect((await s.get(at(fullyConfirmed, "read"))).entry?.value).toBe(1);
	simulated.loseNextReply();
	await expect(s.put(at(fullyConfirmed, "refused"), 1, never)).rejects.toThrow();
	expect((await s.putIfAbsent(at(fullyConfirmed, "refused"), 2, never)).kind).toBe("exists");
	await simulated.failover();
	expect((await s.get(at(fullyConfirmed, "refused"))).entry?.value).toBe(1);
});

it("rebuilds what it keeps as it was written, on the clock of the time it was written", async () => {
	const { simulated, s } = await open();
	await s.put(key("ended"), 1, { expiry: { kind: "after", ms: 1000 } });
	const deadline = (await s.now()) + 1000;
	expect((await s.put(key("met"), 1, { ...never, deadline })).kind).toBe("written");
	simulated.shiftClock(5000);
	expect((await s.get(key("ended"))).entry).toBeNull();
	await simulated.restart();
	expect((await s.get(key("ended"))).entry).toBeNull();
	expect((await s.get(key("met"))).entry?.value).toBe(1);
	await simulated.failover();
	expect((await s.get(key("ended"))).entry).toBeNull();
	expect((await s.get(key("met"))).entry?.value).toBe(1);
});

it("never names a version twice, even one a failover lost", async () => {
	const { simulated, s } = await open();
	const first = await s.put(key("v"), 1, never);
	if (first.kind !== "written") throw new Error("setup");
	simulated.stallReplicas(true);
	await expect(
		s.replaceIf(key("v"), first.version, 2, { expiry: { kind: "keep" } }),
	).rejects.toThrow();
	const lost = (await s.get(key("v"))).entry?.version ?? "";
	simulated.stallReplicas(false);
	await simulated.failover();
	expect((await s.replaceIf(key("v"), first.version, 3, { expiry: { kind: "keep" } })).kind).toBe(
		"written",
	);
	expect((await s.replaceIf(key("v"), lost, 4, { expiry: { kind: "keep" } })).kind).toBe(
		"conflict",
	);
	expect((await s.get(key("v"))).entry?.value).toBe(3);
});

it("keeps writes made side by side as they were made, through a failover and a restart", async () => {
	const { simulated, s } = await open();
	simulated.loseNextReply();
	await expect(s.put(key("old"), 1, never)).rejects.toThrow();
	simulated.shiftClock(5000);
	const started = await s.now();
	const names = ["a", "b", "c", "d"];
	await Promise.all(
		names.map((name) => s.put(key(name), name, { expiry: { kind: "after", ms: 1000 } })),
	);
	const seen = async () => Promise.all(names.map(async (name) => (await s.get(key(name))).entry));
	const written = await seen();
	expect(written.map((entry) => entry?.value)).toEqual(names);
	await simulated.failover();
	expect(await seen()).toEqual(written);
	await simulated.restart();
	expect(await seen()).toEqual(written);
	expect(await s.now()).toBe(started);
});

it("answers a confirmed read only with what is confirmed, even beside a write whose answer is lost", async () => {
	const { simulated, s } = await open([fullyConfirmed]);
	const raced = at(fullyConfirmed, "raced");
	simulated.loseNextReply();
	const [read] = await Promise.all([s.get(raced), s.put(raced, 1, never).catch(() => undefined)]);
	await simulated.failover();
	expect((await s.get(raced)).entry?.value).toBe(read.entry?.value);
});

it("keeps a refusing answer under its mark, so a resend after a failover gets it again", async () => {
	const { simulated, s } = await open();
	const deadline = (await s.now()) + 10_000;
	const marked = { idempotency: "mark", deadline };
	expect((await s.take(key("t"), marked)).kind).toBe("missing");
	await s.put(key("confirming"), 1, never);
	await simulated.failover();
	await s.put(key("t"), 2, never);
	expect((await s.take(key("t"), marked)).kind).toBe("missing");
	expect((await s.get(key("t"))).entry?.value).toBe(2);
});

it("keeps what it answered written through a failover, a restart or memory pressure that comes meanwhile", async () => {
	for (const fault of ["failover", "restart", "pressMemory"] as const) {
		for (let ticks = 0; ticks < 6; ticks++) {
			const { simulated, s } = await open();
			simulated.loseNextReply();
			await expect(s.put(key("old"), 1, never)).rejects.toThrow();
			const writing = s.put(key("new"), 2, never).then(
				(answer) => answer.kind,
				() => "unavailable",
			);
			// Let the write advance this many microtasks before the fault comes.
			for (let i = 0; i < ticks; i++) await Promise.resolve();
			const faulting = simulated[fault]();
			const answered = await writing;
			await faulting;
			const kept = (await s.get(key("new"))).entry?.value;
			if (answered === "written") expect(kept, `${fault} ${ticks}`).toBe(2);
		}
	}
});

it("lets another client act after a write applies and before it is confirmed", async () => {
	const { simulated, s } = await open();
	let seen: unknown;
	simulated.beforeConfirm("put", space.name, async () => {
		seen = (await s.get(key("applied"))).entry?.value;
		await simulated.failover();
	});
	await expect(s.put(key("applied"), 1, never)).rejects.toThrow();
	expect(seen).toBe(1);
	expect((await s.get(key("applied"))).entry).toBeNull();

	simulated.beforeConfirm("put", space.name, async () => {
		await s.put(key("other"), 1, never);
	});
	expect((await s.put(key("first"), 1, never)).kind).toBe("written");
	await simulated.failover();
	expect((await s.get(key("first"))).entry?.value).toBe(1);
});

it("holds a write while replicas are stalled, answering others meanwhile, then answers unavailable", async () => {
	const { simulated, s } = await open();
	await s.put(key("other"), 1, never);
	simulated.stallReplicas(true);
	let settled = false;
	const waiting = s.put(key("held"), 1, never).finally(() => {
		settled = true;
	});
	await new Promise((resolve) => setTimeout(resolve, 20));
	expect((await s.get(key("other"))).entry?.value).toBe(1);
	expect(settled).toBe(false);
	await expect(waiting).rejects.toThrow();
	simulated.stallReplicas(false);
});

it("loses on a restart or under memory pressure what the declared space allows, whatever a key claims", async () => {
	const declared: Space = { name: "volatile", guarantees: ["replicated"] };
	const { simulated, s } = await open([declared]);
	const claimed: Space = { name: "volatile", guarantees: ["no-eviction", "durable", "replicated"] };
	for (const fault of ["restart", "pressMemory"] as const) {
		const k = at(claimed, fault);
		await s.put(k, 1, never);
		await simulated[fault]();
		expect((await s.get(k)).entry, fault).toBeNull();
	}
});

it("rebuilds a write from what it took, whatever the caller changes in its value afterwards", async () => {
	const { simulated, s } = await open();
	const value = { n: 1 };
	const writing = s.put(key("doc"), value, never);
	value.n = 2;
	await writing;
	value.n = 3;
	expect((await s.get(key("doc"))).entry?.value).toEqual({ n: 1 });
	await simulated.restart();
	expect((await s.get(key("doc"))).entry?.value).toEqual({ n: 1 });
	await simulated.failover();
	expect((await s.get(key("doc"))).entry?.value).toEqual({ n: 1 });
});

it("replays a write on the time the primary decided it, so a failover keeps what it answered", async () => {
	let time = now;
	let ticking = false;
	// Each read of this clock moves it a second while ticking.
	const clock = {
		now: () => {
			const read = time;
			if (ticking) time += 1000;
			return read;
		},
	};
	const { simulated, s } = await open([space], clock);
	const deadline = time + 500;
	ticking = true;
	const answer = await s.put(key("timed"), 1, { ...never, deadline });
	ticking = false;
	const expected = answer.kind === "written" ? 1 : null;
	await s.put(key("confirming"), 1, never);
	await simulated.failover();
	expect((await s.get(key("timed"))).entry?.value ?? null).toBe(expected);
	await simulated.restart();
	expect((await s.get(key("timed"))).entry?.value ?? null).toBe(expected);
});

it("applies each write once on a replica, however many later writes confirm it", async () => {
	const { simulated, s } = await open();
	await s.count(key("hits"), { ms: 60_000, limit: 10 });
	await s.put(key("a"), 1, never);
	await s.put(key("b"), 1, never);
	await simulated.failover();
	expect(await s.count(key("hits"), { ms: 60_000, limit: 10 })).toMatchObject({ count: 2 });
});

it("keeps what was confirmed through two failovers in a row", async () => {
	const { simulated, s } = await open();
	await s.put(key("a"), 1, never);
	await simulated.failover();
	await s.put(key("b"), 1, never);
	await simulated.failover();
	expect((await s.get(key("a"))).entry?.value).toBe(1);
});

it("loses on a restart an unconfirmed write in a space that is not durable", async () => {
	const { simulated, s, lacking } = await openWith();
	simulated.loseNextReply();
	await expect(s.put(at(lacking.durable, "a"), 1, never)).rejects.toThrow();
	await simulated.restart();
	expect((await s.get(at(lacking.durable, "a"))).entry).toBeNull();
});

it("answers a refusal in a replicated space without confirmed reads while replicas stall", async () => {
	const { simulated, s } = await open();
	await s.put(key("a"), 1, never);
	simulated.stallReplicas(true);
	expect((await s.putIfAbsent(key("a"), 2, never)).kind).toBe("exists");
	simulated.stallReplicas(false);
});

it("adds up shifts of its clock", async () => {
	const { simulated, s } = await open();
	simulated.shiftClock(1000);
	simulated.shiftClock(1000);
	expect(await s.now()).toBe(now + 2000);
});
