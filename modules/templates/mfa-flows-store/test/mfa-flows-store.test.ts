import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	type StoredTransaction,
	storedLifetimeMaxMs,
	transactionListings,
	transactionStore,
} from "@mod/mfa-flows";
import { transactionListingsContract, transactionStoreContract } from "@mod/mfa-flows/testing";
import { secretRecordsIn } from "@mod/records";
import { type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";
import { section } from "../src/section.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

/** The wiring on a simulated replicated store at a phase, its kernel clock the given one. */
async function opened(
	phase: "reader" | "indexed" = "reader",
	options: {
		readonly blip?: boolean;
		readonly config?: object;
		readonly clock?: () => number;
	} = {},
) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(options.blip ?? false);
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	const app = await assemble({
		modules: [simulated.module, wiring, asker],
		config: { ...kernelConfig(), ...options.config },
		runtime: options.clock ? quietRuntime({ clock: { now: options.clock } }) : runtime,
	});
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { simulated, app, ready };
}

for (const phase of ["reader", "indexed"] as const) {
	transactionStoreContract(
		`mfa-flows-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { simulated, app } = await opened(phase);
			const transactions = app.get(transactionStore);
			return {
				transactions,
				advance: (ms) => simulated.shiftClock(ms),
				raceNextUpdate: (key, change) =>
					// A bounded record is fenced at its create alone: a change is a batch on its own partition, in either phase.
					simulated.beforeNext("batch", "mfa-flows-store.transactions", async () => {
						await transactions.update(key, (record) => ({ value: change(record) }));
					}),
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
				holds: (text) => simulated.holds(text),
			};
		},
	);
}

// The listings' own kernel clock; the simulated store runs on it, so lifetimes and the store's run together.
let listingsNow = 1_800_000_000_000;

for (const phase of ["reader", "indexed"] as const) {
	transactionListingsContract(
		`mfa-flows-store on subject-records' keyed sets, ${phase}, on a simulated replicated store, keeping the section's 7 a holder`,
		async () => {
			const { simulated, app } = await opened(phase, {
				config: { "mfa-flows-store": { "transactions-per-holder": 7 } },
				clock: () => listingsNow,
			});
			return {
				listings: app.get(transactionListings),
				cap: 7,
				advance: (ms) => {
					listingsNow += ms;
				},
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
			};
		},
	);
}

it("fences a subject's transactions until the bound, refusing a new one for the subject, and erases its listings", async () => {
	const { app } = await opened("indexed");
	const [transactions, listings] = [app.get(transactionStore), app.get(transactionListings)];
	const record = (n: number) => ({ n }) as unknown as StoredTransaction;
	await transactions.save("t1", record(1), 60_000, "alice");
	await listings.add("login:alice", "m1", 60_000, "alice");
	const signal = new AbortController().signal;
	expect(await transactions.erase?.("alice", signal)).toMatchObject({ kind: "fenced" });
	expect(await listings.erase?.("alice", signal)).toMatchObject({ kind: "erased", removed: 1 });
	expect(await listings.members("login:alice")).toEqual([]);
	expect(await transactions.save("t2", record(2), 60_000, "alice")).toBe("erased");
	expect(await listings.add("login:alice", "m2", 60_000, "alice")).toBe("erased");
	expect(await transactions.save("t3", record(3), 60_000, "bob")).toBe("created");
	// One kept before the erasure ends by its own end, within the bound.
	expect(await transactions.read("t1")).toEqual(record(1));
});

it("keeps nothing past mfa-flows' bound, the longer of a transaction's and a release permit's", async () => {
	const transactions = (await opened("indexed")).app.get(transactionStore);
	const record = { n: 1 } as unknown as StoredTransaction;
	await expect(
		transactions.save("t", record, storedLifetimeMaxMs + 1, "alice"),
	).rejects.toBeInstanceOf(TypeError);
	expect(await transactions.save("p", record, storedLifetimeMaxMs, "alice")).toBe("created");
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await opened("indexed", { blip: true });
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});

it("keeps 5 transactions a holder unless the section says, from 1 to 10000", () => {
	expect(section.parse({})).toEqual({ "transactions-per-holder": 5 });
	const takes = (n: unknown) => section.safeParse({ "transactions-per-holder": n }).success;
	expect([0, 1, 10_000, 10_001, 2.5].map(takes)).toEqual([false, true, true, false, false]);
});

it("declares, for the listings, each guarantee mfa-flows needs, confirmed reads among them", async () => {
	const declared = contract<readonly Space[]>("declared");
	const reader = defineModule({ name: "reader", replicaSafe: true, takes: [spaces] }, (m) => [
		m.provide(declared).by(async (c) => c.collect(spaces)),
	]);
	const app = await assemble({
		modules: [simulatedStore().module, wiring, reader],
		config: kernelConfig(),
		runtime,
	});
	const listed = app.get(declared).find((s) => s.name === "mfa-flows-store.transaction-listings");
	expect(listed?.guarantees).toEqual(["no-eviction", "durable", "replicated", "confirmed-reads"]);
});

it("reads, in either phase, a transaction a 0.19 node saved through records under a secret on the same space", async () => {
	for (const phase of ["reader", "indexed"] as const) {
		const held = contract<{ readonly store: Store; readonly spaces: readonly Space[] }>("held");
		const holder = defineModule(
			{ name: "holder", replicaSafe: false, takes: [store, spaces] },
			(m) => [
				m.provide(held).by(async (c) => ({
					store: await c.get(store),
					spaces: await c.collect(spaces),
				})),
			],
		);
		const simulated = simulatedStore();
		if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
		const app = await assemble({
			modules: [simulated.module, wiring, holder],
			config: kernelConfig(),
			runtime,
		});
		const { store: kept, spaces: declared } = app.get(held);
		const space = declared.find((s) => s.name === "mfa-flows-store.transactions");
		const random = { bytes: (n: number) => new Uint8Array(n).fill(7) };
		// The space as 0.19 declared it: the same name and guarantees, no subject data stated, so its keys.
		const { subjectData: _, boundedMs: __, erasedBy: ___, ...as019 } = space as Space;
		const before = secretRecordsIn<StoredTransaction>({ store: kept, space: as019, random });
		const record = { n: 19 } as unknown as StoredTransaction;
		expect(await before.create("t-0.19", record, 60_000)).toBe("created");
		const transactions = app.get(transactionStore);
		expect(await transactions.read("t-0.19")).toEqual(record);
		expect(
			await transactions.update("t-0.19", () => ({ value: { n: 20 } as never })),
		).toMatchObject({
			after: { n: 20 },
		});
	}
});
