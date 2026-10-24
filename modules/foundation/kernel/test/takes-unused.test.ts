import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
	BootRefused,
	contract,
	defineModule,
	extensionPoint,
	kernelConfig,
} from "../src/contract.ts";
import { takesUnused } from "../src/testing.ts";

const single = kernelConfig();

describe("takesUnused, a test's view of the takes no factory took", () => {
	const keys = contract<string>("keys");
	const revoked = contract<string>("revoked");
	const steps = extensionPoint<string>("steps", { multiplicity: "many" });
	const provider = defineModule({ name: "provider", takes: [] }, (m) => [
		m.provide(keys).by(() => "k"),
		m.provide(revoked).by(() => "r"),
		m.contribute(steps).by(() => "s"),
	]);

	it("names each declared handle no factory took, by module, and none it took", async () => {
		const stale = defineModule({ name: "stale", takes: [keys, revoked, steps] }, (m) => [
			m.provide(contract<string>("used")).by(async (c) => {
				await c.collect(steps);
				return c.get(keys);
			}),
		]);
		expect(await takesUnused({ modules: [provider, stale], config: single })).toEqual({
			stale: ["revoked"],
		});
	});

	it("answers each section's takes by the section it is given", async () => {
		const tokens = defineModule(
			{
				name: "tokens",
				section: z.object({ revocation: z.enum(["denylist", "family"]) }),
				takes: (s) => (s.revocation === "denylist" ? [keys, revoked] : [keys]),
			},
			(m) => [
				m
					.provide(contract<string>("issued"))
					.by(async (c) => (c.section.revocation === "denylist" ? c.get(revoked) : c.get(keys))),
			],
		);
		const at = (revocation: string) =>
			takesUnused({ modules: [provider, tokens], config: { ...single, tokens: { revocation } } });
		expect(await at("denylist")).toEqual({ tokens: ["keys"] });
		expect(await at("family")).toEqual({});
	});

	it("stops the assembly it built before it answers, so what a factory opened is closed", async () => {
		const held = { opened: 0, closed: 0 };
		const pool = defineModule({ name: "pool", takes: [] }, (m) => [
			m.provide(contract<string>("pool")).by((c) => {
				held.opened += 1;
				c.onStop(() => {
					held.closed += 1;
				});
				return "pool";
			}),
		]);
		expect(await takesUnused({ modules: [pool], config: single })).toEqual({});
		expect(held).toEqual({ opened: 1, closed: 1 });
	});

	it("counts what the assembly took alone, never a take a stop hook makes after", async () => {
		const stopping = defineModule({ name: "stopping", takes: [keys] }, (m) => [
			m.provide(contract<string>("closing")).by((c) => {
				c.onStop(async () => {
					await c.get(keys);
				});
				return "closing";
			}),
		]);
		expect(await takesUnused({ modules: [provider, stopping], config: single })).toEqual({
			stopping: ["keys"],
		});
	});

	it("leaves out a module without takes, and refuses as the boot does", async () => {
		const older = defineModule({ name: "older" }, (m) => [
			m.provide(contract<string>("o")).by(() => "o"),
		]);
		expect(await takesUnused({ modules: [provider, older], config: single })).toEqual({});
		await expect(
			takesUnused({
				modules: [defineModule({ name: "needy", takes: [contract("gone")] })],
				config: single,
			}),
		).rejects.toSatisfy(BootRefused.is);
	});
});
