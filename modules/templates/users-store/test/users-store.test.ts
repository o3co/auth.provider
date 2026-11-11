import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { contactStore, linkStore, type StoredName } from "@mod/users";
import { contactStoreContract, linkStoreContract } from "@mod/users/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

async function opened() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
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
	return { app, simulated, faults };
}

linkStoreContract("users-store on records, on a simulated replicated store", async () => {
	const { app, simulated, faults } = await opened();
	const records = app.get(linkStore);
	return {
		records,
		...faults,
		raceNextUpdate: (key, change) =>
			simulated.beforeNext("replaceIf", "users-store.links", async () => {
				await records.update(key, (record) => ({ value: change(record) }));
			}),
	};
});

contactStoreContract("users-store on records, on a simulated replicated store", async () => {
	const { app, simulated, faults } = await opened();
	const records = app.get(contactStore);
	return {
		records,
		...faults,
		raceNextUpdate: (key, change) =>
			simulated.beforeNext("replaceIf", "users-store.contacts", async () => {
				await records.update(key, (record) => ({ value: change(record) }));
			}),
	};
});

it("offers names' own records apart from the links, and unowned keeping a name's raw in the link space", async () => {
	const { app } = await opened();
	const links = app.get(linkStore);
	const key = JSON.stringify({ idp: "corp" });
	const issuer = { issuer: "https://a.example" } as unknown as StoredName;
	expect(await links.unowned?.(key, issuer, "endless")).toBe("created");
	expect(await links.unowned?.(key, issuer, "endless")).toBe("exists");
	expect(await links.read(key)).toEqual({ issuer: "https://a.example" });
	expect(await links.names?.read(key)).toBeUndefined();
	expect(await links.names?.save(key, issuer, "endless")).toBe("created");
	expect(await links.names?.read(key)).toEqual({ issuer: "https://a.example" });
});
