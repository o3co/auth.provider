import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { contactStore, linkStore, type StoredName } from "@mod/users";
import { contactStoreContract, linkStoreContract } from "@mod/users/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

/** The wiring over a simulated store, its records in the phase given; and the composition's readiness. */
async function opened(phase: "reader" | "indexed" = "reader", blip = false) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(blip);
	let context: BuildContext<unknown> | undefined;
	const app = await assemble({
		modules: [
			simulated.module,
			wiring,
			defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
				m.provide(contract<object>("asker")).by((c) => {
					context = c;
					return {};
				}),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const faults = {
		advance: (ms: number) => simulated.shiftClock(ms),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
		stallReplicas: (on: boolean) => simulated.stallReplicas(on),
	};
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { app, simulated, faults, ready };
}

for (const phase of ["reader", "indexed"] as const) {
	// A change in indexed records watches its subject's tombstone: a batch across.
	const write = phase === "indexed" ? "batchAcross" : "batch";
	linkStoreContract(
		`users-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { app, simulated, faults } = await opened(phase);
			const records = app.get(linkStore);
			return {
				records,
				...faults,
				raceNextUpdate: (key, change) =>
					simulated.beforeNext(write, "users-store.links", async () => {
						await records.update(key, (record) => ({ value: change(record) }));
					}),
			};
		},
	);

	contactStoreContract(
		`users-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { app, simulated, faults } = await opened(phase);
			const records = app.get(contactStore);
			return {
				records,
				...faults,
				raceNextUpdate: (key, change) =>
					simulated.beforeNext(write, "users-store.contacts", async () => {
						await records.update(key, (record) => ({ value: change(record) }));
					}),
			};
		},
	);
}

const nameKey = JSON.stringify({ idp: "corp" });
const issuer = { issuer: "https://a.example" } as unknown as StoredName;

it("offers every port as one set: names apart from the links, and unowned keeping a name's record raw while not indexed", async () => {
	const { app } = await opened();
	const links = app.get(linkStore);
	for (const port of [links.remove, links.erase, links.migrate, links.names, links.unowned]) {
		expect(port).toBeDefined();
	}
	expect(await links.unowned?.(nameKey, issuer, "endless")).toBe("created");
	expect(await links.unowned?.(nameKey, issuer, "endless")).toBe("exists");
	expect(await links.read(nameKey)).toEqual({ issuer: "https://a.example" });
	expect(await links.names?.read(nameKey)).toBeUndefined();
	expect(await links.names?.save(nameKey, issuer, "endless")).toBe("created");
	expect(await links.names?.read(nameKey)).toEqual({ issuer: "https://a.example" });
});

it("answers closed for a name's record once indexed, writing nothing in the link space", async () => {
	const { app } = await opened("indexed");
	const links = app.get(linkStore);
	expect(await links.unowned?.(nameKey, issuer, "endless")).toBe("closed");
	expect(await links.read(nameKey)).toBeUndefined();
});

it("keeps the composition out of traffic while the phase cannot be read, and in once it can", async () => {
	const { simulated, ready } = await opened("indexed", true);
	expect(await ready()).not.toBe("ready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});
