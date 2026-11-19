import { erasureMaintenance } from "@mod/account-erasure";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	type Space,
	type Store,
	type StoreUpkeep,
	spaces,
	store,
	storeControl,
	storeUpkeep,
} from "@mod/store";
import storeModule from "@mod/store/module";
import { plantValue } from "@mod/store/testing";
import { subjectRecordsPhase } from "@mod/subject-records";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const held: Space = {
	name: "erasure-store-test.held",
	guarantees: ["no-eviction"],
	subjectData: "online-keyed",
	erasedBy: "erasure-store-test",
	requiredOnceErasing: true,
};
const owner = defineModule({ name: "erasure-store-test", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => held),
]);

/** The wiring over store's memory store, with one declared space. */
async function opened() {
	const app = await assemble({
		modules: [storeModule, owner, wiring],
		config: { ...kernelConfig(), store: { "accept-volatile": true } },
		runtime: quietRuntime(),
	});
	return {
		maintenance: await app.get(erasureMaintenance),
		upkeep: await app.get(storeUpkeep),
		control: await app.get(storeControl),
		app,
	};
}

it("answers the control record, the key and marks in erasure's words, each answer a copy of store's", async () => {
	const { maintenance, control } = await opened();
	const before = await maintenance.record();
	expect(before).toMatchObject({ maintenance: false, requires: [] });
	const entered = await maintenance.enter();
	expect(entered).toEqual({ kind: "entered", epoch: expect.any(String) });
	expect(await maintenance.mark("erasure-store-test.mark", { n: 1 })).toEqual({ kind: "marked" });
	const record = await maintenance.record();
	expect(record).toMatchObject({ epoch: entered.epoch, maintenance: true });
	expect(record.marks["erasure-store-test.mark"]).toEqual({
		value: { n: 1 },
		epoch: entered.epoch,
	});
	expect(record).toEqual(await control.control());
	expect(record).not.toBe(await control.control());
	expect(await maintenance.require([held.name])).toEqual({ kind: "required" });
	expect(await maintenance.leave()).toEqual({ kind: "left" });
});

it("answers the ledger, honours and alone as store does", async () => {
	const { maintenance, upkeep } = await opened();
	expect(await maintenance.kept()).toEqual(await upkeep.kept());
	expect(await maintenance.retire("erasure-store-test.gone")).toEqual({
		kind: "not-in-maintenance",
	});
	expect(await maintenance.honours(["no-eviction"])).toEqual(await upkeep.honours(["no-eviction"]));
	expect(await maintenance.alone()).toEqual({ kind: "alone" });
});

it("walks a declared space by its name, handing on store's keys, and refuses any other name", async () => {
	const { maintenance, app } = await opened();
	const key = { space: held, partition: "p", name: "k" };
	await plantValue(await app.get(store), key, 1, { kind: "never" });
	const page = await maintenance.sweep(held.name);
	expect(page.keys).toEqual([key]);
	expect(page.server).toEqual(expect.any(String));
	await expect(maintenance.sweep("erasure-store-test.undeclared")).rejects.toBeInstanceOf(
		TypeError,
	);
});

it("reads the phase, and writes subject-records' mark under the key alone", async () => {
	const { maintenance, control } = await opened();
	expect(await maintenance.phase()).toBe("reader");
	expect(await maintenance.writePhase()).toEqual({ kind: "not-in-maintenance" });
	await maintenance.enter();
	expect(await maintenance.writePhase()).toEqual({ kind: "written" });
	expect((await control.control()).marks[subjectRecordsPhase.mark]?.value).toBe("indexed");
	expect(await maintenance.phase()).toBe("indexed");
});

it("answers the declared spaces by name, guarantees and erasure fields, each a copy of store's", async () => {
	const { maintenance, upkeep } = await opened();
	const declared = maintenance.declared();
	expect(declared).toEqual([
		{
			name: held.name,
			guarantees: ["no-eviction"],
			subjectData: "online-keyed",
			erasedBy: "erasure-store-test",
			requiredOnceErasing: true,
		},
	]);
	expect(declared[0]).not.toBe(upkeep.declared()[0]);
	expect(Object.isFrozen(declared)).toBe(true);
});

it("refuses the boot over a store offering no control record, both store contracts being required", async () => {
	// Never built: kernel refuses the composition as it checks the takes.
	const withoutControl = defineModule(
		{ name: "store-without-control", replicaSafe: true, takes: [] },
		(m) => [
			m.provide(store).by(() => ({}) as Store),
			m.provide(storeUpkeep).by(() => ({}) as StoreUpkeep),
		],
	);
	const refused = await assemble({
		modules: [withoutControl, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toContainEqual({
		where: "account-erasure-store",
		reason: expect.stringContaining("store.control"),
	});
});
