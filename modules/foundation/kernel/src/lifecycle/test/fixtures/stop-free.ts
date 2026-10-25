// A host stopping an assembly whose stop hook never ends: the stop holds nothing, so the process ends on its own.
import { assemble, contract, defineModule, kernelConfig } from "../../../contract.ts";

const holding = defineModule({ name: "holding", takes: [] }, (m) => [
	m.provide(contract<void>("held")).by((c) => {
		c.onStop(() => new Promise<void>(() => {}));
	}),
]);
const app = await assemble({ modules: [holding], config: kernelConfig() });
// Were the stop's deadline to keep the process, it would end only after a minute, by this exit.
void app.stop(60_000).then(() => process.exit(3));
