import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { transactionListings, transactionStore } from "@mod/mfa-flows";
import { transactionListingsContract, transactionStoreContract } from "@mod/mfa-flows/testing";
import { type Space, spaces } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";
import { section } from "../src/section.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

transactionStoreContract(
	"mfa-flows-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const transactions = app.get(transactionStore);
		return {
			transactions,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (key, change) =>
				simulated.beforeNext("replaceIf", "mfa-flows-store.transactions", async () => {
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

// The listings' own kernel clock; the simulated store runs on it, so lifetimes and the store's run together.
let listingsNow = 1_800_000_000_000;
const listingsRuntime = quietRuntime({ clock: { now: () => listingsNow } });

transactionListingsContract(
	"mfa-flows-store on records' keyed sets, on a simulated replicated store, keeping the section's 7 a holder",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: { ...kernelConfig(), "mfa-flows-store": { "transactions-per-holder": 7 } },
			runtime: listingsRuntime,
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
