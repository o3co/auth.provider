import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor } from "@mod/records/testing";
import {
	closingList,
	cookieIndex,
	type StoredSession,
	sessionStore,
	subjectSessions,
} from "@mod/session-lifecycle";
import { sessionStoreContract } from "@mod/session-lifecycle/testing";
import { type Space, spaces } from "@mod/store";
import { type SimulatedStore, simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

// Smaller than the defaults, so a full shard is reached only if the section is read.
const closingsSize = { shards: 4, perShard: 3 };

// The kernel's clock; the simulated store's runs on it, so the listings' lifetimes and the records' run together.
let now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });

/** The wiring on a simulated replicated store at a phase, with what the contract test does to the store. */
async function assembled(phase: "reader" | "indexed" = "reader", blip = false) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(blip);
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	const app = await assemble({
		modules: [simulated.module, wiring, asker],
		config: {
			...kernelConfig(),
			"session-store": {
				"closing-shards": closingsSize.shards,
				"closings-per-shard": closingsSize.perShard,
			},
		},
		runtime,
	});
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { app, simulated, ready, ...storeSide(simulated) };
}

const storeSide = (simulated: SimulatedStore) => ({
	advance: (ms: number) => {
		now += ms;
	},
	crowd: { limit: closingsSize.perShard, handles: crowdingFor(closingsSize).jobs },
	loseNextAnswer: () => simulated.loseNextReply(),
	failover: () => simulated.failover(),
	restart: () => simulated.restart(),
	pressMemory: () => simulated.pressMemory(),
	holds: (text: string) => simulated.holds(text),
});

for (const phase of ["reader", "indexed"] as const) {
	// A session's change in indexed records watches its subject's tombstone: a batch across.
	const sessionWrite = phase === "indexed" ? "batchAcross" : "batch";
	sessionStoreContract(
		`session-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { app, simulated, ready: _, ...side } = await assembled(phase);
			const sessions = app.get(sessionStore);
			return {
				...side,
				sessions,
				cookies: app.get(cookieIndex),
				closings: app.get(closingList),
				subjects: app.get(subjectSessions),
				raceNextUpdate: (handle, change) =>
					simulated.beforeNext(sessionWrite, "session-store.sessions", async () => {
						await sessions.update(handle, (record) => ({ value: change(record) }));
					}),
			};
		},
	);
}

it("erases a subject's sessions and listing, telling each record removed, and fences both for the subject alone", async () => {
	const { app } = await assembled("indexed");
	const [sessions, subjects] = [app.get(sessionStore), app.get(subjectSessions)];
	const session = (n: number) => ({ n }) as unknown as StoredSession;
	await sessions.save("h1", session(1), 60_000, "alice");
	await sessions.save("h2", session(2), 60_000, "bob");
	await subjects.add("alice", "h1", 60_000);
	const signal = new AbortController().signal;
	const told: StoredSession[] = [];
	expect(await sessions.erase?.("alice", signal, (record) => told.push(record))).toMatchObject({
		kind: "erased",
		removed: 1,
	});
	expect(told).toEqual([session(1)]);
	expect(await subjects.erase?.("alice", signal)).toMatchObject({ kind: "erased", removed: 1 });
	expect(await subjects.members("alice")).toEqual([]);
	expect(await sessions.save("h3", session(3), 60_000, "alice")).toBe("erased");
	expect(await subjects.add("alice", "h3", 60_000)).toBe("erased");
	expect(await sessions.read("h2")).toEqual(session(2));
});

it("migrates the listing, keyed by its subject, as nothing to do, never reading it", async () => {
	const { app } = await assembled("indexed");
	const walk = { sweep: async () => ({ keys: [], server: "one" }) };
	const unread = async () => ({ kind: "unreadable" as const, reason: "never read" });
	const report = await app
		.get(subjectSessions)
		.migrate?.(walk, unread, new AbortController().signal);
	expect(report).toEqual({
		kind: "migrated",
		space: "session-store.subjects",
		indexed: 0,
		removed: 0,
	});
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await assembled("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});

it("confirms its reads of each subject's sessions, so a revocation never reads a list older than a login", async () => {
	const declared = contract<readonly Space[]>("declared");
	const reader = defineModule({ name: "reader", replicaSafe: true, takes: [spaces] }, (m) => [
		m.provide(declared).by(async (c) => c.collect(spaces)),
	]);
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring, reader],
		config: kernelConfig(),
		runtime,
	});
	const subjects = app.get(declared).find((s) => s.name === "session-store.subjects");
	expect(subjects?.guarantees).toEqual(
		expect.arrayContaining(["no-eviction", "durable", "replicated", "confirmed-reads"]),
	);
});
