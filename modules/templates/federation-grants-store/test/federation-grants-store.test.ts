import {
	type GrantStore,
	grantStore,
	type PendingIntents,
	pendingIntents,
	refreshLockStore,
	type SubjectGrants,
	stepStore,
	subjectGrants,
} from "@mod/federation-grants";
import { grantStoreContract, refreshLockStoreContract } from "@mod/federation-grants/testing";
import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";
import { section } from "../src/section.ts";

for (const phase of ["reader", "indexed"] as const) {
	// A grant's write in indexed records watches its subject's tombstone: a batch across.
	const grantWrite = phase === "indexed" ? "batchAcross" : "batch";
	grantStoreContract(
		`federation-grants-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			let now = 1_800_000_000_000;
			const runtime = quietRuntime({ clock: { now: () => now } });
			const simulated = simulatedStore();
			if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
			const app = await assemble({
				modules: [simulated.module, wiring],
				config: {
					...kernelConfig(),
					"federation-grants-store": { "pending-per-client-and-subject": 3 },
				},
				runtime,
			});
			const grants = app.get(grantStore);
			return {
				grants,
				steps: app.get(stepStore),
				pending: app.get(pendingIntents),
				subjects: app.get(subjectGrants),
				cap: 3,
				// The simulated store reads the composition's clock, as keyed sets do.
				advance: (ms) => {
					now += ms;
				},
				raceNextChange: (id, change) =>
					simulated.beforeNext(grantWrite, "federation-grants-store.grants", async () => {
						await grants.change(id, (record) => ({ value: change(record) }));
					}),
				failover: () => simulated.failover(),
				duringNextCreate: (during) =>
					simulated.beforeConfirm(grantWrite, "federation-grants-store.grants", during),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
				holds: (text) => simulated.holds(text),
			};
		},
	);
}

refreshLockStoreContract(
	"federation-grants-store on records, on a simulated replicated store",
	async () => {
		let now = 1_800_000_000_000;
		const runtime = quietRuntime({ clock: { now: () => now } });
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		return {
			locks: app.get(refreshLockStore),
			advance: (ms) => {
				now += ms;
			},
			pressMemory: () => simulated.pressMemory(),
		};
	},
);

it("keeps 16 intents waiting to a pair unless told otherwise, from 1 to 1000", () => {
	expect(section.parse({})).toMatchObject({ "pending-per-client-and-subject": 16 });
	for (const bad of [0, 1001, 1.5]) {
		expect(section.safeParse({ "pending-per-client-and-subject": bad }).success).toBe(false);
	}
	// The cap counts per client and subject; the name that said per subject is refused, not ignored.
	expect(section.safeParse({ "pending-per-subject": 3 }).success).toBe(false);
});

it("lists 100 grants a subject unless told otherwise, from 1 to 10000", () => {
	expect(section.parse({})).toMatchObject({ "grants-per-subject": 100 });
	for (const bad of [0, 10_001, 1.5]) {
		expect(section.safeParse({ "grants-per-subject": bad }).success).toBe(false);
	}
	expect(section.parse({ "grants-per-subject": 10_000 })).toBeDefined();
});

/** The wiring indexed on a simulated store, unreachable at first where `blip`, with its readiness. */
async function indexedOpen(blip = false) {
	const simulated = simulatedStore();
	simulated.mark("subject-records.phase", "indexed");
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
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { app, simulated, ready };
}

it("erases a subject's grants, pending pairs and listing, refusing new ones for the subject and leaving another's", async () => {
	const { app } = await indexedOpen();
	const [grants, pending, subjects] = [grantStore, pendingIntents, subjectGrants].map((one) =>
		app.get(one as never),
	) as [GrantStore, PendingIntents, SubjectGrants];
	const record = (n: number) => ({ n }) as never;
	await grants.create("g1", record(1), 60_000, "alice");
	await grants.create("g2", record(2), 60_000, "bob");
	await pending.add("c\nalice", "g1", 60_000, "alice");
	await subjects.add("alice", "g1", 60_000);
	const signal = new AbortController().signal;
	for (const store of [grants, pending, subjects]) {
		expect(await store.erase?.("alice", signal)).toMatchObject({ kind: "erased", removed: 1 });
	}
	expect(await grants.read("g1")).toBeUndefined();
	expect(await subjects.members("alice")).toEqual([]);
	expect(await grants.create("g3", record(3), 60_000, "alice")).toBe("erased");
	expect(await pending.add("c\nalice", "g3", 60_000, "alice")).toBe("erased");
	expect(await subjects.add("alice", "g3", 60_000)).toBe("erased");
	expect(await grants.read("g2")).toEqual(record(2));
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await indexedOpen(true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});
