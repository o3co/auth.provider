import { describe, expect, it } from "vitest";
import type { Key, Space, Store } from "../contract.ts";
import {
	type ContractKit,
	overwrite,
	type StoreHarness,
	sleep,
} from "../contract-harness/harness.ts";
import { subjectWriter } from "../writer/subject-writer.ts";

/** The store contract's scanning a space, and the checks on every input. */
export function walkingContract(harness: StoreHarness, kit: ContractKit): void {
	const { space, replicated, fresh, never } = kit;
	describe("scanning a space", () => {
		const walk = async (s: Store, target: Space, between?: () => Promise<void>) => {
			const seen = new Map<string, number>();
			let cursor: string | undefined;
			do {
				const page = await s.scan(target, cursor);
				for (const k of page.keys) {
					expect(k.space.name).toBe(target.name);
					const id = `${k.partition}/${k.name}`;
					seen.set(id, (seen.get(id) ?? 0) + 1);
				}
				cursor = page.cursor;
				await between?.();
			} while (cursor !== undefined);
			return seen;
		};

		it("lists each live value's key in the space, over pages, and no counter, set or other space", async () => {
			const s = await harness.open();
			// Names of the longest length, so each cursor given, which may name a key, is taken back.
			const live = Array.from({ length: 250 }, (_, i) =>
				fresh(space, `q${i % 7}`.padEnd(512, "q"))(`k${i}`.padEnd(512, "k")),
			);
			for (const k of live) await overwrite(s, k, 1, never);
			const { now } = await s.get(fresh()("probe"));
			const ends = now + 30;
			await overwrite(s, fresh()("gone"), 1, { expiry: { kind: "at", at: ends } });
			while ((await s.now()) <= ends) await sleep(5);
			await overwrite(s, fresh(replicated)("elsewhere"), 1, never);
			await s.count(fresh()("counted"), { ms: 60_000, limit: 5 });
			const seen = await walk(s, space);
			expect([...seen.keys()].sort()).toEqual(live.map((k) => `${k.partition}/${k.name}`).sort());
			expect([...(await walk(s, replicated)).keys()]).toHaveLength(1);
			expect([...(await walk(await harness.open(), space)).keys()]).toEqual([]);
		});

		it("lists every key that lives through the walk, whatever is written or removed meanwhile", async () => {
			const s = await harness.open();
			const kept = Array.from({ length: 120 }, (_, i) => fresh(space, "w")(`kept${i}`));
			const dropped = Array.from({ length: 120 }, (_, i) => fresh(space, "w")(`dropped${i}`));
			for (const k of [...kept, ...dropped]) await overwrite(s, k, 1, never);
			let n = 0;
			const seen = await walk(s, space, async () => {
				const k = dropped[n];
				if (k) await s.removeIf(k, { value: 1 });
				await overwrite(s, fresh(space, "w")(`added${n++}`), 1, never);
			});
			for (const k of kept) expect(seen.get(`w/${k.name}`), k.name).toBeGreaterThanOrEqual(1);
		});

		it("refuses a space that is not declared", async () => {
			const s = await harness.open();
			await expect(
				s.scan({ name: "undeclared", guarantees: [], subjectData: "none" }),
			).rejects.toThrow();
		});
	});

	describe("input checks", () => {
		it("refuses times, durations and limits that are not whole numbers in range", async () => {
			const s = await harness.open();
			const k = fresh()("a");
			await expect(overwrite(s, k, 1, { expiry: { kind: "after", ms: 1.5 } })).rejects.toThrow(
				TypeError,
			);
			await expect(overwrite(s, k, 1, { expiry: { kind: "at", at: -1 } })).rejects.toThrow(
				TypeError,
			);
			await expect(s.putIfAbsent(k, 1, { ...never, deadline: 0.5 })).rejects.toThrow(TypeError);
			await expect(
				s.batch([], [{ key: k, put: 1, expiry: { kind: "after", ms: Number.NaN } }]),
			).rejects.toThrow(TypeError);
			await expect(s.count(k, { ms: 10.5, limit: 1 })).rejects.toThrow(TypeError);
			expect((await s.get(k)).entry).toBeNull();
		});

		it("accepts only plain JSON values and applies nothing of a batch with one bad value", async () => {
			const s = await harness.open();
			const key = fresh();
			for (const bad of [
				undefined,
				Number.NaN,
				Number.POSITIVE_INFINITY,
				new Date(0),
				new Map(),
				() => 1,
			]) {
				await expect(overwrite(s, key("a"), bad as never, never)).rejects.toThrow(TypeError);
			}
			await expect(
				s.batch(
					[],
					[
						{ key: key("b"), put: 1, expiry: { kind: "never" } },
						{ key: key("c"), put: { at: new Date(0) } as never, expiry: { kind: "never" } },
					],
				),
			).rejects.toThrow(TypeError);
			for (const name of ["a", "b", "c"]) expect((await s.get(key(name))).entry).toBeNull();
			await expect(
				overwrite(
					s,
					{
						space: { name: "undeclared", guarantees: [], subjectData: "none" },
						partition: "p",
						name: "a",
					},
					1,
					never,
				),
			).rejects.toThrow(TypeError);
		});

		it("refuses malformed inputs to every operation", async () => {
			const s = await harness.open();
			const k = fresh()("a");
			await expect(s.replaceIf(k, "", 1, never)).rejects.toThrow(TypeError);
			await expect(s.removeIf(k, { version: 1 as never })).rejects.toThrow(TypeError);
			await expect(s.count(k, { ms: 1000, limit: -1 })).rejects.toThrow(TypeError);
			await expect(s.take(k, { deadline: -1 })).rejects.toThrow(TypeError);
		});

		it("refuses options with unknown or hidden properties", async () => {
			const s = await harness.open();
			const k = fresh()("a");
			await expect(overwrite(s, k, 1, { ...never, deadlin: 1 } as never)).rejects.toThrow(
				TypeError,
			);
			const hidden = Object.defineProperty({ ...never }, "deadline", {
				value: 0,
				enumerable: false,
			});
			await expect(overwrite(s, k, 1, hidden)).rejects.toThrow(TypeError);
			await expect(s.count(k, { ms: 1000, limit: 1, extra: 1 } as never)).rejects.toThrow(
				TypeError,
			);
		});

		it("refuses batch options with an accessor, a hidden or an unknown property, a writer among them or not", async () => {
			const s = await harness.open();
			const k = fresh()("a");
			const writes = [{ key: k, put: 1, ...never }];
			const deadline = [
				{ get: () => Date.now() + 60_000, enumerable: true },
				{ value: Date.now() + 60_000, enumerable: false },
			];
			for (const writer of [undefined, subjectWriter]) {
				const bad = [
					...deadline.map((d) => Object.defineProperty({ writer }, "deadline", d)),
					{ writer, extra: 1 },
				] as never[];
				for (const options of bad) {
					await expect(s.batch([], writes, options)).rejects.toThrow(TypeError);
					if (s.batchAcross) {
						await expect(s.batchAcross([], writes, options)).rejects.toThrow(TypeError);
					}
				}
			}
			expect((await s.get(k)).entry).toBeNull();
		});

		it("takes only well-formed strings and keeps non-ASCII keys and members apart, in code point order", async () => {
			const s = await harness.open();
			const key = fresh();
			const lone = "\uD800";
			await expect(overwrite(s, key(lone), 1, never)).rejects.toThrow(TypeError);
			await expect(overwrite(s, key("a"), lone, never)).rejects.toThrow(TypeError);
			await expect(overwrite(s, key("a"), { [lone]: 1 }, never)).rejects.toThrow(TypeError);
			await expect(s.putIfAbsent(key("a"), 1, { ...never, idempotency: lone })).rejects.toThrow(
				TypeError,
			);
			await overwrite(s, key("é😀"), "é😀", never);
			expect((await s.get(key("é😀"))).entry?.value).toBe("é😀");
			expect((await s.get(key("e😀"))).entry).toBeNull();
		});

		it("refuses values and arguments that are not plain data read once", async () => {
			const s = await harness.open();
			const key = fresh();
			class Point {
				x = 1;
			}
			const extra = Object.assign([1], { note: "x" });
			const proto = JSON.parse('{"__proto__": 1}');
			const getter = Object.defineProperty({}, "x", { get: () => 1, enumerable: true });
			for (const bad of [new Point(), extra, proto, getter]) {
				await expect(overwrite(s, key("a"), bad as never, never)).rejects.toThrow(TypeError);
			}
			const sneaky = Object.defineProperty({ space, partition: "p" }, "name", {
				get: () => "a",
				enumerable: true,
			});
			await expect(s.get(sneaky as Key)).rejects.toThrow(TypeError);
			await overwrite(s, key("z"), -0, never);
			expect(Object.is((await s.get(key("z"))).entry?.value, 0)).toBe(true);
			await expect(
				s.batch(
					[],
					[
						{ key: key("b"), put: 1, expiry: { kind: "never" } },
						{ key: key("b"), put: 2, expiry: { kind: "never" } },
					],
				),
			).rejects.toThrow(TypeError);
		});

		it("refuses each malformed part of a key, an option, a value, a condition and a member", async () => {
			const s = await harness.open();
			const k = fresh()("a");
			class Items extends Array<number> {}
			const trailingHole = [1];
			trailingHole.length = 2;
			const holeAndExtra = Object.assign([1], { x: 1 });
			holeAndExtra.length = 2;
			let deep: unknown = 1;
			for (let i = 0; i < 100; i++) deep = [deep];
			const hiddenDeadline = Object.defineProperty({ ...never }, "deadline", {
				get: () => 1,
				enumerable: true,
			});
			const refused: Record<string, () => Promise<unknown>> = {
				"long key name": () => s.get(fresh()("x".repeat(513))),
				"empty partition": () => s.get({ ...k, partition: "" }),
				"time past the last date": () =>
					overwrite(s, k, 1, { expiry: { kind: "at", at: 8.65e15 } }),
				"limit past its range": () => s.count(k, { ms: 1000, limit: 1_000_000_001 }),
				"zero duration": () => overwrite(s, k, 1, { expiry: { kind: "after", ms: 0 } }),
				"unknown expiry": () => overwrite(s, k, 1, { expiry: { kind: "forever" } as never }),
				"option with a getter": () => overwrite(s, k, 1, hiddenDeadline),
				"batch option": () => s.batch([], [], { deadline: 0.5 }),
				"symbol key in a value": () => overwrite(s, k, { [Symbol("x")]: 1 } as never, never),
				"array subclass": () => overwrite(s, k, Items.from([1]) as never, never),
				"array with a trailing hole": () => overwrite(s, k, trailingHole, never),
				"array with a hole and a property": () => overwrite(s, k, holeAndExtra, never),
				"array with a symbol": () =>
					overwrite(s, k, Object.assign([1], { [Symbol("x")]: 1 }), never),
				"value nested too deeply": () => overwrite(s, k, deep as never, never),
				"value expected by a removal": () => s.removeIf(k, { value: new Date(0) as never }),
				"empty condition version": () => s.batch([{ key: k, version: "" }], []),
				"condition with neither": () => s.batch([{ key: k } as never], []),
			};
			for (const [label, run] of Object.entries(refused)) {
				await expect(run(), label).rejects.toThrow(TypeError);
			}
			expect((await s.get(k)).entry).toBeNull();
		});
	});
}
