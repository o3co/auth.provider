import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { upstreamLoginReceivers } from "@mod/upstreams";
import { expect, it } from "vitest";
import { handoff, handoffSealing, heldLoginStore, noHandoff } from "../src/contract.ts";
import handoffModule from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 0 } });
const unusedStore = defineModule({ name: "held" }, (m) => [
	m.provide(heldLoginStore).by(() => ({
		save: async () => "created" as const,
		update: async () => undefined,
		remove: async () => {},
	})),
]);

it("is no handoff where no module receives upstream tokens, asking for no seal", async () => {
	const app = await assemble({
		modules: [unusedStore, handoffModule],
		config: kernelConfig(),
		runtime,
	});
	expect(app.get(handoff)).toBe(noHandoff);
});

it("hands tokens over where a module receives them, over the composed seal", async () => {
	const told: string[] = [];
	const receiver = defineModule({ name: "receiver" }, (m) => [
		m.contribute(upstreamLoginReceivers).by(() => ({
			name: "one",
			received: async (at) => void told.push(at.tokens.accessToken),
			withdrawn: async () => {},
		})),
	]);
	const app = await assemble({
		modules: [unusedStore, sealModule, receiver, handoffModule],
		config: { ...kernelConfig(), ...sealConfig() },
		runtime,
	});
	const session = { id: "s", context: { subject: "alice", amr: [], authenticatedAt: 0 } };
	await app
		.get(handoff)
		.of("corp", "alice", { accessToken: "a", tokenType: "Bearer", scope: [] }, 1000)
		?.after({ kind: "opened", session } as never);
	expect(told).toEqual(["a"]);
});

const receiver = defineModule({ name: "receiver" }, (m) => [
	m.contribute(upstreamLoginReceivers).by(() => ({
		name: "one",
		received: async () => {},
		withdrawn: async () => {},
	})),
]);
/** A seal that records the context of each value it seals. */
const recording = (sealed: string[]): Seal => ({
	seal: (plain, context) => {
		sealed.push(context.split("\n")[0] ?? "");
		return plain;
	},
	open: (value) => ({ kind: "opened", plain: value }),
});
const sealing = (name: string, value: Seal) =>
	defineModule({ name }, (m) => [m.contribute(handoffSealing).by(() => value)]);
const tokens = { accessToken: "a", tokenType: "Bearer", scope: [] };

it("seals a held login's tokens with the sealing contributed, asking for no seal", async () => {
	const sealed: string[] = [];
	const app = await assemble({
		modules: [unusedStore, receiver, sealing("sealing", recording(sealed)), handoffModule],
		config: kernelConfig(),
		runtime,
	});
	await app
		.get(handoff)
		.of("corp", "alice", tokens, 1000)
		?.after({ kind: "held" } as never);
	expect(sealed).toEqual(["upstream-handoff.held-login"]);
});

it("refuses to boot two sealings where a module receives upstream tokens", async () => {
	const refused = await assemble({
		modules: [
			unusedStore,
			receiver,
			sealing("one", recording([])),
			sealing("two", recording([])),
			handoffModule,
		],
		config: kernelConfig(),
		runtime,
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual([
		{ where: "upstream-handoff", reason: "more than one sealing is contributed" },
	]);
});
