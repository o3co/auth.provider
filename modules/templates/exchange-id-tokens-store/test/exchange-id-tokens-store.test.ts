import { usedIdTokens } from "@mod/exchange-id-tokens";
import { usedIdTokensContract } from "@mod/exchange-id-tokens/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

usedIdTokensContract(
	"exchange-id-tokens-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		return {
			used: app.get(usedIdTokens),
			advance: (ms) => simulated.shiftClock(ms),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			restart: () => simulated.restart(),
			pressMemory: () => simulated.pressMemory(),
		};
	},
);
