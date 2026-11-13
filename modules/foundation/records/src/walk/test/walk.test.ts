import type { Walk as ToolWalk } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Key, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import fc from "fast-check";
import { expect, expectTypeOf, it } from "vitest";
import { recordsIn, type Walk } from "../../records.ts";
import { memoryRecords } from "../../testing.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });
const space: Space = { name: "walk-test", guarantees: ["no-eviction", "durable", "replicated"] };
const other: Space = { name: "walk-test-other", guarantees: space.guarantees };
const opened = contract<Store>("walk-test.store");
type Counted = { readonly n: number };

/** Records in `space` over a simulated store, `count` of them, and a record in another space. */
async function open(count: number) {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "user", replicaSafe: false, takes: [store] }, (m) => [
				m.contribute(spaces).by(() => space),
				m.contribute(spaces).by(() => other),
				m.provide(opened).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const s = app.get(opened);
	const random = { bytes: (n: number) => new Uint8Array(n).fill(7) };
	const records = recordsIn<Counted>({ store: s, space, random });
	for (let n = 0; n < count; n += 1) await records.create(`k${n}`, { n }, 60_000);
	await recordsIn<Counted>({ store: s, space: other, random }).create(
		"elsewhere",
		{ n: -1 },
		60_000,
	);
	/** Every key of the walked space and the other, in one order, `per` to a page; `serverOf` names each page's server. */
	const walkOf = (per: number, serverOf: (asked: number) => string): Walk => {
		let asked = 0;
		let all: Key[] | undefined;
		return {
			sweep: async (name, cursor) => {
				if (all === undefined) {
					all = [];
					for (const scanned of [space, other]) {
						let on: string | undefined;
						do {
							const page = await s.scan(scanned, on);
							all.push(...page.keys);
							on = page.cursor;
						} while (on !== undefined);
					}
					all.sort((a, b) => (String(a.partition) < String(b.partition) ? -1 : 1));
				}
				expect(name).toBe(space.name);
				const at = cursor === undefined ? 0 : Number(cursor);
				const keys = all.slice(at, at + per);
				const server = serverOf(asked++);
				return at + per < all.length
					? { keys, cursor: String(at + per), server }
					: { keys, server };
			},
		};
	};
	return { simulated, records, walkOf };
}

const steady = () => "one";

it("hands over each record's value of its space alone, once walked", async () => {
	const { records, walkOf } = await open(5);
	const seen: number[] = [];
	expect(await records.walk(walkOf(2, steady), (v) => (seen.push(v.n), true))).toEqual({
		kind: "walked",
	});
	expect(seen.sort()).toEqual([0, 1, 2, 3, 4]);
});

it("stops where the visitor answers false", async () => {
	const { records, walkOf } = await open(5);
	let seen = 0;
	expect(await records.walk(walkOf(2, steady), () => ++seen < 2)).toEqual({ kind: "stopped" });
	expect(seen).toBe(2);
});

it("starts over on a page from another server, and never ends at the change", async () => {
	const { records, walkOf } = await open(4);
	const seen = new Set<number>();
	const walked = await records.walk(
		walkOf(1, (asked) => (asked < 2 ? "one" : "two")),
		(v) => (seen.add(v.n), true),
	);
	expect(walked).toEqual({ kind: "walked" });
	expect([...seen].sort()).toEqual([0, 1, 2, 3]);
});

it("answers unfinished, walk-unsteady, once the server changed more than eight times", async () => {
	const { records, walkOf } = await open(4);
	const walked = await records.walk(
		walkOf(1, (asked) => (asked % 2 === 0 ? "one" : "two")),
		() => true,
	);
	expect(walked).toEqual({ kind: "unfinished", reason: "walk-unsteady" });
});

it("answers unfinished, aborted, on the caller's signal", async () => {
	const { records, walkOf } = await open(3);
	const stop = new AbortController();
	const walked = await records.walk(walkOf(1, steady), () => (stop.abort(), true), stop.signal);
	expect(walked).toEqual({ kind: "unfinished", reason: "aborted" });
});

it("answers unfinished, unavailable, when the store cannot read a record", async () => {
	const { simulated, records, walkOf } = await open(3);
	const walk = walkOf(5, steady);
	await walk.sweep(space.name);
	simulated.unreachable(true);
	expect(await records.walk(walk, () => true)).toEqual({
		kind: "unfinished",
		reason: "unavailable",
	});
});

it("offers the walk in memory too, handing over each living record", async () => {
	let now = 0;
	const { records } = memoryRecords<Counted>(() => now, { shards: 1, perShard: 1 });
	await records.create("short", { n: 1 }, 10);
	await records.create("long", { n: 2 }, 60_000);
	now += 10;
	const seen: number[] = [];
	expect(await records.walk({} as Walk, (v) => (seen.push(v.n), true))).toEqual({ kind: "walked" });
	expect(seen).toEqual([2]);
});

it("takes the walk a maintenance tool hands in, as erasure-extensions declares it", () => {
	expectTypeOf<ToolWalk>().toExtend<Walk>();
});

it("walks every record once it finishes, and answers walk-unsteady only past eight start-overs", async () => {
	await fc.assert(
		fc.asyncProperty(
			fc.integer({ min: 1, max: 6 }),
			fc.integer({ min: 1, max: 3 }),
			fc.array(fc.integer({ min: 0, max: 40 }), { maxLength: 14 }),
			async (count, per, flips) => {
				const { records, walkOf } = await open(count);
				const at = new Set(flips);
				let server = "one";
				const servers: string[] = [];
				const walk = walkOf(per, (asked) => {
					if (at.has(asked)) server = server === "one" ? "two" : "one";
					servers.push(server);
					return server;
				});
				const seen = new Set<number>();
				const walked = await records.walk(walk, (v) => (seen.add(v.n), true));
				const changes = servers.filter((s, i) => i > 0 && s !== servers[i - 1]).length;
				if (walked.kind === "walked") {
					expect(seen.size).toBe(count);
					expect(changes).toBeLessThanOrEqual(8);
					// The last page was taken on the server its walk started on.
					expect(servers.at(-1)).toBe(servers.at(-2) ?? servers.at(-1));
				} else {
					expect(walked).toEqual({ kind: "unfinished", reason: "walk-unsteady" });
					expect(changes).toBeGreaterThan(8);
				}
			},
		),
		{ numRuns: 60 },
	);
}, 60_000);
