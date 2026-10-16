import { transactionStore } from "@mod/federation";
import { transactionStoreContract } from "@mod/federation/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

transactionStoreContract(
	"federation-store on records, on a simulated replicated store",
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
			raceNextUpdate: (name, change) =>
				simulated.beforeNext("replaceIf", "federation-store.transactions", async () => {
					await transactions.update(name, (record) => ({ value: change(record) }));
				}),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			holds: (text) => simulated.holds(text),
		};
	},
);
