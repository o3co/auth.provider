import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { transactionStore } from "@mod/mfa-flows";
import { transactionStoreContract } from "@mod/mfa-flows/testing";
import { simulatedStore } from "@mod/store/testing";
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
