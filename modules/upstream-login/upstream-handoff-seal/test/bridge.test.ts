import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Seal, seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { handoffSealing } from "@mod/upstream-handoff";
import { expect, it } from "vitest";
import bridge from "../src/module.ts";

const runtime = quietRuntime();
const seen = contract<readonly Seal[]>("test.seen");
const reader = defineModule({ name: "reader" }, (m) => [
	m.provide(seen).by((c) => c.collect(handoffSealing)),
]);

it("contributes the composed seal as the handoff's sealing", async () => {
	const app = await assemble({
		modules: [sealModule, bridge, reader],
		config: { ...kernelConfig(), ...sealConfig() },
		runtime,
	});
	expect(app.get(seen)).toEqual([app.get(seal)]);
	expect(app.get(seen)[0]).toBe(app.get(seal));
});

it("refuses to boot where no seal is composed", async () => {
	const refused = await assemble({
		modules: [bridge, reader],
		config: kernelConfig(),
		runtime,
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
});
