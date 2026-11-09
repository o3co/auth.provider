import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Key, Space, Store } from "../contract.ts";
import type { StoreControl, StoreUpkeep } from "./upkeep.ts";

/** One process over a store's data: the store and its upkeep, sharing the epoch it took. */
export interface UpkeepProcess {
	readonly store: Store;
	readonly control: StoreControl;
	readonly upkeep: StoreUpkeep;
}

export interface UpkeepHarness {
	/** A process over fresh, empty data, declaring `declared`. */
	start(declared: readonly Space[]): Promise<UpkeepProcess>;
	/** Another process over the same data as `process`, declaring `declared`, taking the record's epoch as it starts. */
	another(process: UpkeepProcess, declared: readonly Space[]): Promise<UpkeepProcess>;
	/** For a store that holds expired keys until removed: whether the data still holds `key` at all. */
	holds?(process: UpkeepProcess, key: Key): Promise<boolean>;
}

/** The spaces the upkeep contract test declares: holding no subject's data, holding some, and undeclared. */
export const upkeepSpaces: readonly Space[] = Object.freeze([
	{ name: "upkeep", guarantees: [], subjectData: "none" },
	{ name: "upkeep-held", guarantees: [], subjectData: "online-indexed" },
	{ name: "upkeep-plain", guarantees: [] },
]);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const never = { expiry: { kind: "never" } } as const;

/** The upkeep contract, run against any implementation offering it. */
export function upkeepContract(name: string, harness: UpkeepHarness): void {
	const [none, held, plain] = upkeepSpaces as [Space, Space, Space];
	let n = 0;
	const fresh = (space: Space = none): Key => ({ space, partition: `p${++n}`, name: "k" });
	const pair = async () => {
		const first = await harness.start(upkeepSpaces);
		return [first, await harness.another(first, upkeepSpaces)] as const;
	};

	describe(`store upkeep contract: ${name}`, () => {
		describe("the control record", () => {
			it("starts with no epoch, no maintenance key, no space required and no mark", async () => {
				const p = await harness.start(upkeepSpaces);
				expect(await p.control.control()).toEqual({
					epoch: null,
					maintenance: false,
					requires: [],
					marks: {},
				});
			});

			it("keeps each mark with the epoch it was written in, through later epochs", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.mark("test.before", { at: 1 });
				const { epoch } = await p.upkeep.enterMaintenance();
				await p.upkeep.mark("test.after", "two");
				expect((await p.control.control()).marks).toEqual({
					"test.before": { value: { at: 1 }, epoch: null },
					"test.after": { value: "two", epoch },
				});
			});

			it("sets a new epoch on each entry to maintenance, and keeps it on leaving", async () => {
				const p = await harness.start(upkeepSpaces);
				const first = await p.upkeep.enterMaintenance();
				const second = await p.upkeep.enterMaintenance();
				expect(second.epoch).not.toBe(first.epoch);
				expect(await p.control.control()).toMatchObject({
					epoch: second.epoch,
					maintenance: true,
				});
				expect(await p.upkeep.leaveMaintenance()).toEqual({ kind: "left" });
				expect(await p.control.control()).toMatchObject({
					epoch: second.epoch,
					maintenance: false,
				});
			});

			it("replaces the spaces required, under the maintenance key alone", async () => {
				const p = await harness.start(upkeepSpaces);
				expect(await p.upkeep.require([none.name])).toEqual({ kind: "not-in-maintenance" });
				expect((await p.control.control()).requires).toEqual([]);
				await p.upkeep.enterMaintenance();
				expect(await p.upkeep.require([none.name, held.name])).toEqual({ kind: "required" });
				await p.upkeep.require([held.name]);
				expect((await p.control.control()).requires).toEqual([held.name]);
			});

			it("refuses to require no space", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				await expect(p.upkeep.require([])).rejects.toThrow(TypeError);
			});
		});

		describe("a process under an old epoch", () => {
			it("changes nothing, through every change, and still reads", async () => {
				const [p, old] = await pair();
				const k = fresh();
				await old.store.putIfAbsent(k, 1, never);
				const version = (await old.store.get(k)).entry?.version ?? "";
				await p.upkeep.enterMaintenance();
				const refused: (() => Promise<unknown>)[] = [
					() => old.store.putIfAbsent(fresh(), 1, never),
					() => old.store.replaceIf(k, version, 2, never),
					() => old.store.removeIf(k, { version }),
					() => old.store.take(k),
					() => old.store.batch([], [{ key: k, remove: true }]),
					() => old.store.count(fresh(), { ms: 1000, limit: 5 }),
					() => old.upkeep.mark("test.old", true),
					() => old.upkeep.enterMaintenance(),
					() => old.upkeep.leaveMaintenance(),
					() => old.upkeep.require([none.name]),
					() => old.upkeep.retire("gone"),
					() => old.upkeep.sweep(none),
				];
				if (old.store.batchAcross) {
					refused.push(async () => old.store.batchAcross?.([], [{ key: k, remove: true }]));
				}
				for (const change of refused) await expect(change()).rejects.toBeInstanceOf(Unavailable);
				expect((await old.store.get(k)).entry?.value).toBe(1);
				expect((await p.store.get(k)).entry?.value).toBe(1);
				expect((await p.control.control()).marks).toEqual({});
				expect((await old.control.control()).maintenance).toBe(true);
			});

			it("does not replay an answer kept under its mark", async () => {
				const [p, old] = await pair();
				const k = fresh();
				const marked = { ...never, idempotency: "once" };
				expect((await old.store.putIfAbsent(k, 1, marked)).kind).toBe("written");
				await p.upkeep.enterMaintenance();
				await expect(old.store.putIfAbsent(k, 1, marked)).rejects.toBeInstanceOf(Unavailable);
			});

			it("is followed by processes that start under the new epoch and change as before", async () => {
				const [p] = await pair();
				await p.upkeep.enterMaintenance();
				const next = await harness.another(p, upkeepSpaces);
				expect((await next.store.putIfAbsent(fresh(), 1, never)).kind).toBe("written");
				expect(await next.upkeep.mark("test.next", 1)).toEqual({ kind: "marked" });
			});
		});

		describe("the ledger", () => {
			it("holds each declared space once a process starts, with whether it may hold a subject's data", async () => {
				const p = await harness.start(upkeepSpaces);
				expect([...(await p.upkeep.kept())].sort((a, b) => (a.name < b.name ? -1 : 1))).toEqual([
					{ name: none.name, subjectDataEver: false },
					{ name: held.name, subjectDataEver: true },
					{ name: plain.name, subjectDataEver: true },
				]);
			});

			it("never turns a space back to holding no subject's data", async () => {
				const p = await harness.start(upkeepSpaces);
				await harness.another(p, [{ ...none, subjectData: "online-keyed" }]);
				await harness.another(p, [none, { ...held, subjectData: "none" }]);
				const kept = new Map((await p.upkeep.kept()).map((s) => [s.name, s.subjectDataEver]));
				expect(kept.get(none.name)).toBe(true);
				expect(kept.get(held.name)).toBe(true);
			});

			it("retires a space no longer declared, never one the process declares", async () => {
				const p = await harness.start(upkeepSpaces);
				const fewer = await harness.another(p, [none]);
				expect(await fewer.upkeep.retire(held.name)).toEqual({ kind: "not-in-maintenance" });
				await fewer.upkeep.enterMaintenance();
				expect(await fewer.upkeep.retire(held.name)).toEqual({ kind: "retired" });
				expect(await fewer.upkeep.retire(none.name)).toEqual({ kind: "declared" });
				expect(await fewer.upkeep.retire("never-declared")).toEqual({ kind: "missing" });
				expect((await p.upkeep.kept()).map((s) => s.name).sort()).toEqual([none.name, plain.name]);
			});
		});

		describe("honours", () => {
			it("verifies a want of no guarantee", async () => {
				const p = await harness.start(upkeepSpaces);
				expect(await p.upkeep.honours([])).toEqual({ kind: "verified" });
			});

			it("refuses a guarantee it does not know", async () => {
				const p = await harness.start(upkeepSpaces);
				await expect(p.upkeep.honours(["fast" as never])).rejects.toThrow(TypeError);
			});
		});

		describe("sweep", () => {
			it("walks every live key of the space by pages, each naming the same server", async () => {
				const p = await harness.start(upkeepSpaces);
				const keys = Array.from({ length: 150 }, (_, i) => ({
					space: held,
					partition: `sweep${n}`,
					name: `k${i}`,
				}));
				n++;
				for (const k of keys) await p.store.putIfAbsent(k, 1, never);
				const seen = new Set<string>();
				const servers = new Set<string>();
				let cursor: string | undefined;
				do {
					const page = await p.upkeep.sweep(held, cursor);
					for (const k of page.keys) seen.add(`${k.partition}/${k.name}`);
					servers.add(page.server);
					cursor = page.cursor;
				} while (cursor !== undefined);
				for (const k of keys) expect(seen.has(`${k.partition}/${k.name}`)).toBe(true);
				expect(servers.size).toBe(1);
			});

			it("removes for good an expired key it meets, and lists it no more", async () => {
				const p = await harness.start(upkeepSpaces);
				const k = fresh(plain);
				await p.store.putIfAbsent(k, 1, { expiry: { kind: "after", ms: 20 } });
				await sleep(40);
				let cursor: string | undefined;
				do {
					const page = await p.upkeep.sweep(plain, cursor);
					expect(page.keys.some((at) => at.partition === k.partition)).toBe(false);
					cursor = page.cursor;
				} while (cursor !== undefined);
				if (harness.holds) expect(await harness.holds(p, k)).toBe(false);
			});
		});
	});
}
