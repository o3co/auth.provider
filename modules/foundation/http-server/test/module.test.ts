import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { httpServers } from "../src/contract.ts";
import server from "../src/module.ts";

const config = { ...kernelConfig(), ...httpConfig() };

it("takes every handle its takes name: the points it collects itself", async () => {
	expect((await takesUnused({ modules: [http, server], config }))["http-server"]).toBeUndefined();
});

it("is the one server http's httpServers takes", async () => {
	const counted = contract<number>("test.servers");
	const counting = defineModule(
		{ name: "counting", replicaSafe: false, takes: [httpServers] },
		(m) => [m.provide(counted).by(async (c) => (await c.collect(httpServers)).length)],
	);
	const app = await assemble({
		modules: [http, server, counting],
		config,
		runtime: quietRuntime({ clock: { now: () => 0 }, random: { bytes: (n) => new Uint8Array(n) } }),
	});
	expect(app.get(counted)).toBe(1);
});
