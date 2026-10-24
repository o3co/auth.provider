// A host whose only handle is a stop hook that never ends: the refusal still reaches it, after the deadline.
import { assemble, BootRefused, contract, defineModule, kernelConfig } from "../../src/contract.ts";

const held = contract<void>("held");
const holding = defineModule({ name: "holding" }, (m) => [
	m.provide(held).by((c) => {
		c.onStop(() => new Promise<void>(() => {}));
	}),
]);
const refusing = defineModule({ name: "refusing" }, (m) => [
	m.provide(contract<void>("refused")).by((c) => c.refuse("refusing", "refused on purpose")),
]);

try {
	await assemble({
		modules: [holding, refusing],
		config: kernelConfig({ "stop-deadline": "1s" }),
	});
} catch (error) {
	if (BootRefused.is(error)) process.exit(78);
	throw error;
}
process.exit(0);
