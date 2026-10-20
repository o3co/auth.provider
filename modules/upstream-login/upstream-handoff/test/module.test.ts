import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import sealModule from "@mod/seal/module";
import { sealConfig } from "@mod/seal/testing";
import { upstreamLoginReceivers } from "@mod/upstreams";
import { expect, it } from "vitest";
import { handoff, heldLoginStore, noHandoff } from "../src/contract.ts";
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
