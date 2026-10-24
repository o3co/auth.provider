import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { transactionListings, transactionStore } from "@mod/mfa-flows";
import { transactionListingsContract, transactionStoreContract } from "@mod/mfa-flows/testing";
import { type Space, spaces } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

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
	"mfa-flows-store on records' keyed sets, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime: listingsRuntime,
		});
		return {
			listings: app.get(transactionListings),
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

it("declares, for the listings, each guarantee mfa-flows needs, confirmed reads among them", async () => {
	const declared = contract<readonly Space[]>("declared");
	const reader = defineModule({ name: "reader", takes: [spaces] }, (m) => [
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
