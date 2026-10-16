import { codeStore, voidList } from "@mod/code-grant";
import { codeStoreContract } from "@mod/code-grant/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor } from "@mod/records/testing";
import { simulatedStore } from "@mod/store/testing";
import wiring from "../src/module.ts";

// Smaller than the defaults, so a full shard is reached only if the section is read.
const voidsSize = { shards: 4, perShard: 3 };

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

codeStoreContract("code-grant-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: {
			...kernelConfig(),
			"code-grant-store": {
				"void-shards": voidsSize.shards,
				"voids-per-shard": voidsSize.perShard,
			},
		},
		runtime,
	});
	const codes = app.get(codeStore);
	return {
		codes,
		voids: app.get(voidList),
		advance: (ms) => simulated.shiftClock(ms),
		raceNextUpdate: (hash, change) =>
			simulated.beforeNext("replaceIf", "code-grant-store.codes", async () => {
				await codes.update(hash, (record) => ({ value: change(record) }));
			}),
		crowd: { limit: voidsSize.perShard, hashes: crowdingFor(voidsSize).jobs },
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
		holds: (text) => simulated.holds(text),
	};
});
