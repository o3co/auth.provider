import { randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Json, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { changeRecords, keyedSetsIn, recordsIn } from "../../records.ts";
import { kept, opened, ownersValue } from "../envelope.ts";

const space: Space = { name: "envelope-test", guarantees: [] };
const held = contract<Store>("test.store");
const clock = { now: () => Date.now() };

/** A place over a store of the space, and its records' raw value by key. */
async function place() {
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "user", replicaSafe: false, takes: [store] }, (m) => [
				m.contribute(spaces).by(() => space),
				m.provide(held).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const s = app.get(held);
	const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
	const at = (key: string, name = "record") => ({ space, partition: key, name });
	return {
		place: { store: s, space, random },
		/** Stores `value` as is, as an indexed writer or an earlier release did. */
		put: async (key: string, value: Json, name?: string) => {
			await s.putIfAbsent(at(key, name), value, { expiry: { kind: "never" } });
		},
		raw: async (key: string, name?: string) => (await s.get(at(key, name))).entry?.value,
	};
}

const envelope = (value: Json) => ({ "records:v": 1, subject: "alice", value });

it("opens an envelope by its exact shape alone, any other value as it is", () => {
	expect(opened(envelope({ a: 1 }))).toEqual({ value: { a: 1 }, subject: "alice" });
	for (const raw of [
		{ "records:v": 1, subject: "alice", value: 1, more: true },
		{ "records:v": 2, subject: "alice", value: 1 },
		{ "records:v": 1, subject: 7, value: 1 },
		{ "records:v": 1, subject: "alice" },
		[1, 2],
		"text",
		true,
		null,
	] as Json[]) {
		expect(opened(raw)).toEqual({ value: raw });
	}
	expect(opened(undefined)).toEqual({ value: undefined });
});

it("keeps a value in the envelope of its subject, and a value without one as it is", () => {
	expect(kept({ a: 1 }, "alice")).toEqual(envelope({ a: 1 }));
	expect(kept({ a: 1 }, undefined)).toEqual({ a: 1 });
	expect(opened(kept([1], "bob"))).toEqual({ value: [1], subject: "bob" });
});

it("refuses an owner's value holding the envelope's mark at its top, and takes one holding it deeper", () => {
	expect(() => ownersValue({ "records:v": 1 })).toThrow(TypeError);
	expect(ownersValue({ inner: { "records:v": 1 } })).toEqual({ inner: { "records:v": 1 } });
});

it("reads a record kept in an envelope as its value, and a change keeps the envelope and its subject", async () => {
	const { place: p, put, raw } = await place();
	await put("k", envelope({ count: 1 }));
	const records = recordsIn<{ count: number }>(p);
	expect(await records.read("k")).toEqual({ count: 1 });
	const changed = await records.change("k", (current) => ({ value: { count: current.count + 1 } }));
	expect(changed).toEqual({ before: { count: 1 }, after: { count: 2 } });
	expect(await raw("k")).toEqual(envelope({ count: 2 }));
	await expect(records.create("m", { "records:v": 1 } as never, 1000)).rejects.toThrow(TypeError);
});

it("reads and writes enveloped records as one through changeRecords, keeping their envelopes", async () => {
	const { place: p, put, raw } = await place();
	await put("a", envelope(1));
	await put("b", 2);
	const changed = await changeRecords({
		targets: [
			{ place: p, key: "a" },
			{ place: p, key: "b" },
		],
		decide: (read) => ({
			targets: read.map((value) => ({ value: (value as number) * 10 })),
		}),
	});
	expect(changed.targets).toEqual([
		{ before: 1, after: 10 },
		{ before: 2, after: 20 },
	]);
	expect(await raw("a")).toEqual(envelope(10));
	expect(await raw("b")).toBe(20);
});

it("reads a keyed set kept in an envelope, and an add keeps the envelope", async () => {
	const { place: p, put, raw } = await place();
	const ends = clock.now() + 60_000;
	await put("set", envelope({ held: [["one", ends]], awaiting: [] }), "set");
	const sets = keyedSetsIn({ ...p, cap: 10, clock });
	expect((await sets.members("set")).map((m) => m.member)).toEqual(["one"]);
	await sets.add("set", "two", 60_000);
	expect((await sets.members("set")).map((m) => m.member)).toEqual(["one", "two"]);
	expect(opened(await raw("set", "set")).subject).toBe("alice");
});
