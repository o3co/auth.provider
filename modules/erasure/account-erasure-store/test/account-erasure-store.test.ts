import { erasureMaintenance } from "@mod/account-erasure";
import { assemble, BootRefused, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import {
	type Space,
	type Store,
	type StoreControl,
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

/**
 * The wiring over a store whose upkeep and control record each record the arguments they are given
 * and answer what no real store would at once, so a member forwarded wrong answers wrong.
 */
async function recorded(answers: Partial<Record<keyof StoreUpkeep | "control", unknown>>) {
	const calls: [string, unknown[]][] = [];
	const answering =
		(member: string) =>
		async (...args: unknown[]) => {
			calls.push([member, args]);
			const answer = answers[member as keyof typeof answers];
			if (answer instanceof Error) throw answer;
			return answer;
		};
	const members = [
		"mark",
		"require",
		"enterMaintenance",
		"leaveMaintenance",
		"kept",
		"retire",
		"honours",
		"sweep",
		"alone",
	] as const;
	const upkeep = Object.fromEntries([
		...members.map((member) => [member, answering(member)]),
		["declared", () => []],
	]) as unknown as StoreUpkeep;
	const control = { control: answering("control") } as unknown as StoreControl;
	const standIn = defineModule({ name: "recording-store", replicaSafe: true, takes: [] }, (m) => [
		m.provide(store).by(() => ({}) as Store),
		m.provide(storeUpkeep).by(() => upkeep),
		m.provide(storeControl).by(() => control),
	]);
	const app = await assemble({
		modules: [standIn, wiring],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	return { maintenance: await app.get(erasureMaintenance), calls };
}

it("forwards retire's name and answers the store's retired", async () => {
	const { maintenance, calls } = await recorded({ retire: { kind: "retired" } });
	expect(await maintenance.retire("erasure-store-test.gone")).toEqual({ kind: "retired" });
	expect(calls).toEqual([["retire", ["erasure-store-test.gone"]]]);
});

it("forwards sweep's name and cursor, answering the later page the store gives", async () => {
	const page = { keys: [{ partition: "p", name: "k2" }], cursor: "c3", server: "s1" };
	const { maintenance, calls } = await recorded({ sweep: page });
	expect(await maintenance.sweep("erasure-store-test.held", "c2")).toEqual(page);
	expect(calls).toEqual([["sweep", ["erasure-store-test.held", "c2"]]]);
});

it("forwards honours' guarantees and answers the store's unmet with its reasons", async () => {
	const unmet = { kind: "unmet", reasons: ["no replica"] };
	const { maintenance, calls } = await recorded({ honours: unmet });
	expect(await maintenance.honours(["durable", "replicated"])).toEqual(unmet);
	expect(calls).toEqual([["honours", [["durable", "replicated"]]]]);
});

it("forwards each other member's arguments to its one counterpart", async () => {
	const { maintenance, calls } = await recorded({
		control: { epoch: "e9", maintenance: true, requires: ["a"], marks: {} },
		mark: { kind: "marked" },
		require: { kind: "required" },
		enterMaintenance: { kind: "entered", epoch: "e9" },
		leaveMaintenance: { kind: "left" },
		kept: [{ name: "a", subjectDataEver: true }],
		alone: { kind: "accompanied", count: 3 },
	});
	expect(await maintenance.record()).toEqual({
		epoch: "e9",
		maintenance: true,
		requires: ["a"],
		marks: {},
	});
	expect(await maintenance.mark("erasure-store-test.mark", [1, "x"])).toEqual({ kind: "marked" });
	expect(await maintenance.require(["a", "b"])).toEqual({ kind: "required" });
	expect(await maintenance.enter()).toEqual({ kind: "entered", epoch: "e9" });
	expect(await maintenance.leave()).toEqual({ kind: "left" });
	expect(await maintenance.kept()).toEqual([{ name: "a", subjectDataEver: true }]);
	expect(await maintenance.alone()).toEqual({ kind: "accompanied", count: 3 });
	expect(calls).toEqual([
		["control", []],
		["mark", ["erasure-store-test.mark", [1, "x"]]],
		["require", [["a", "b"]]],
		["enterMaintenance", []],
		["leaveMaintenance", []],
		["kept", []],
		["alone", []],
	]);
});

it("passes the store's outage through as it is thrown, the same error", async () => {
	const outage = new Unavailable("store");
	const { maintenance } = await recorded({ alone: outage, retire: outage, sweep: outage });
	await expect(maintenance.alone()).rejects.toBe(outage);
	await expect(maintenance.retire("x")).rejects.toBe(outage);
	await expect(maintenance.sweep("x", "c")).rejects.toBe(outage);
});
