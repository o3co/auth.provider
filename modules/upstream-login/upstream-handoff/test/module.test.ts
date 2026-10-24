import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { upstreamLoginReceivers } from "@mod/upstreams";
import { expect, it } from "vitest";
import { handoff, handoffSealing, heldLoginStore, noHandoff } from "../src/contract.ts";
import handoffModule from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 0 } });
const unusedStore = defineModule({ name: "held", takes: [] }, (m) => [
	m.provide(heldLoginStore).by(() => ({
		save: async () => "created" as const,
		update: async () => undefined,
		remove: async () => {},
	})),
]);
/** A receiver of upstream tokens, recording each access token it is told. */
const receiving = (told: string[] = []) =>
	defineModule({ name: "receiver", takes: [] }, (m) => [
		m.contribute(upstreamLoginReceivers).by(() => ({
			name: "one",
			received: async (at) => void told.push(at.tokens.accessToken),
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
	defineModule({ name, takes: [] }, (m) => [m.contribute(handoffSealing).by(() => value)]);
const tokens = { accessToken: "a", tokenType: "Bearer", scope: [] };
const composition = (modules: readonly Module[]) => ({
	modules: [unusedStore, ...modules, handoffModule],
	config: kernelConfig(),
	runtime,
});
const boot = (modules: readonly Module[]) => assemble(composition(modules));

it("takes all it names, a module receiving upstream tokens or none", async () => {
	expect(await takesUnused(composition([]))).toEqual({});
	expect(await takesUnused(composition([receiving(), sealing("sealing", recording([]))]))).toEqual(
		{},
	);
});

it("is no handoff where no module receives upstream tokens, asking for no seal", async () => {
	const app = await boot([]);
	expect(app.get(handoff)).toBe(noHandoff);
});

it("is no handoff where no module receives upstream tokens, a sealing contributed going unused", async () => {
	const sealed: string[] = [];
	const app = await boot([sealing("sealing", recording(sealed))]);
	expect(app.get(handoff)).toBe(noHandoff);
	expect(sealed).toEqual([]);
});

it("hands tokens over where a module receives them", async () => {
	const told: string[] = [];
	const app = await boot([receiving(told), sealing("sealing", recording([]))]);
	const session = { id: "s", context: { subject: "alice", amr: [], authenticatedAt: 0 } };
	await app
		.get(handoff)
		.of("corp", "alice", tokens, 1000)
		?.after({ kind: "opened", session } as never);
	expect(told).toEqual(["a"]);
});

it("seals a held login's tokens with the sealing contributed, asking for no seal", async () => {
	const sealed: string[] = [];
	const app = await boot([receiving(), sealing("sealing", recording(sealed))]);
	await app
		.get(handoff)
		.of("corp", "alice", tokens, 1000)
		?.after({ kind: "held" } as never);
	expect(sealed).toEqual(["upstream-handoff.held-login"]);
});

it("refuses to boot a module receiving upstream tokens with no sealing, though a seal is composed", async () => {
	const refused = await assemble({
		modules: [unusedStore, sealModule, receiving(), handoffModule],
		config: { ...kernelConfig(), ...sealConfig() },
		runtime,
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual([
		{
			where: "upstream-handoff",
			reason:
				"a module receives upstream tokens and no sealing is contributed: compose upstream-handoff-seal",
		},
	]);
});

it("refuses to boot two sealings where a module receives upstream tokens", async () => {
	const refused = await boot([
		receiving(),
		sealing("one", recording([])),
		sealing("two", recording([])),
	]).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual([
		{ where: "upstream-handoff", reason: "more than one sealing is contributed" },
	]);
});
