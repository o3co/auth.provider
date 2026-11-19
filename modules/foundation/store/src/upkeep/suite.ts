import { BootRefused, BuildRefused, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Key, Space, Store } from "../contract.ts";
import { plantValue } from "../planting/planting.ts";
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
	/** Whether the data still holds `key` at all, expired or not. */
	holds?(process: UpkeepProcess, key: Key): Promise<boolean>;
	/** Set where the server removes expired keys itself (as Redis does): what expired may then be gone with no change. */
	readonly expiresOnItsOwn?: true;
	/** Another process over the same data as `process`, granted to build under the maintenance key (a tool's). */
	anotherMayBuildUnderKey(
		process: UpkeepProcess,
		declared: readonly Space[],
	): Promise<UpkeepProcess>;
}

/** The spaces the upkeep contract test declares: holding no subject's data, holding some the subject writer guards, and holding some it does not. */
export const upkeepSpaces: readonly Space[] = Object.freeze([
	{ name: "upkeep", guarantees: [], subjectData: "none" },
	{ name: "upkeep-held", guarantees: [], subjectData: "online-indexed" },
	{ name: "upkeep-plain", guarantees: [], subjectData: "pseudonymous" },
]);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * What a refused start says, from kernel's refusals alone: a library's `BuildRefused` as thrown, or
 * the `BootRefused` an assembly gives; anything else is no refusal and says nothing.
 */
function said(error: unknown): string | undefined {
	if (BuildRefused.is(error)) return `${error.where}: ${error.reason}`;
	if (BootRefused.is(error)) return error.refusals.map((r) => `${r.where}: ${r.reason}`).join("\n");
	return undefined;
}

/** That `start` is refused by kernel's refusal, saying `words`; what it says. */
async function refusedSaying(start: Promise<unknown>, words: RegExp): Promise<string> {
	const refused = await start.then(
		() => undefined,
		(error: unknown) => error,
	);
	const says = said(refused);
	expect(says, `not refused as kernel refuses: ${String(refused)}`).toBeDefined();
	expect(says).toMatch(words);
	return says as string;
}

/** The two refusals of a start, in upkeep's contract's words. */
const underKey = {
	where: "store",
	reason: "only a tool may start while the store is under the maintenance key",
};
const lacking = {
	where: "store",
	reason: "the data requires a space this process does not declare",
};

/** That `start` is refused by kernel's refusal, with exactly `refusal` among what it holds. */
async function refusedAs(
	start: Promise<unknown>,
	refusal: { readonly where: string; readonly reason: string },
): Promise<void> {
	const refused = await start.then(
		() => undefined,
		(error: unknown) => error,
	);
	if (BuildRefused.is(refused)) {
		expect({ where: refused.where, reason: refused.reason }).toEqual(refusal);
	} else {
		expect(BootRefused.is(refused), `not refused as kernel refuses: ${String(refused)}`).toBe(true);
		expect((refused as BootRefused).refusals).toContainEqual(refusal);
	}
}

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

	/**
	 * Where what expired stays held until removed, so a read's leaving it can be seen: `holds` offered
	 * and the server not expiring keys itself.
	 */
	const readsShowHeld = Boolean(harness.holds && !harness.expiresOnItsOwn);

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
			it("answers what expired absent when it reads it, removing nothing, held where that can be seen", async () => {
				const [p, old] = await pair();
				const k = fresh();
				await old.store.putIfAbsent(k, 1, { expiry: { kind: "after", ms: 20 } });
				await p.upkeep.enterMaintenance();
				await sleep(40);
				expect((await old.store.get(k)).entry).toBeNull();
				if (old.store.getMany) expect((await old.store.getMany([k]))[0]?.entry).toBeNull();
				if (readsShowHeld) expect(await harness.holds?.(old, k)).toBe(true);
			});

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
				// Under the key, only a process that may build under it starts.
				const next = await harness.anotherMayBuildUnderKey(p, upkeepSpaces);
				expect((await next.store.putIfAbsent(fresh(), 1, never)).kind).toBe("written");
				expect(await next.upkeep.mark("test.next", 1)).toEqual({ kind: "marked" });
			});
		});

		describe("starting", () => {
			const tool = (p: UpkeepProcess, declared: readonly Space[]) =>
				harness.anotherMayBuildUnderKey(p, declared);

			it("refuses a process that serves under the maintenance key, and starts one that may build under it", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				await refusedAs(harness.another(p, upkeepSpaces), underKey);
				const t = await tool(p, upkeepSpaces);
				expect(await t.upkeep.mark("test.tool", 1)).toEqual({ kind: "marked" });
			});

			it("refuses a process lacking a required space, one that may build under the key outside maintenance too, and starts that one lacking it under the key", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				await p.upkeep.require([held.name]);
				await p.upkeep.leaveMaintenance();
				await refusedAs(harness.another(p, [none]), lacking);
				await refusedAs(tool(p, [none]), lacking);
				// p took its epoch under the key and left it, so it changes no more: another enters.
				const q = await harness.another(p, upkeepSpaces);
				await q.upkeep.enterMaintenance();
				const t = await tool(q, [none]);
				expect(await t.upkeep.mark("test.replacing", 1)).toEqual({ kind: "marked" });
			});

			it("refuses for a required space with store's fixed reason, naming no space, however the names are written", async () => {
				const p = await harness.start(upkeepSpaces);
				const names = ["line\nbreak", "zero\u200bwidth", "store: refused for good"];
				await p.upkeep.enterMaintenance();
				await p.upkeep.require(names);
				await p.upkeep.leaveMaintenance();
				await refusedAs(harness.another(p, [none]), lacking);
				const says = await refusedSaying(harness.another(p, [none]), /./);
				for (const name of names) expect(says).not.toContain(name);
				expect(says).not.toMatch(/break|width|for good/);
			});

			it("refuses on the maintenance key first, where both refusals apply", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				await p.upkeep.require([held.name]);
				await refusedAs(harness.another(p, [none]), underKey);
			});

			it("writes no ledger entry when the maintenance key refuses a start", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				const only: Space = { name: "upkeep-keyed-out", guarantees: [], subjectData: "none" };
				await refusedAs(harness.another(p, [none, only]), underKey);
				expect((await p.upkeep.kept()).map((s) => s.name)).not.toContain(only.name);
			});

			it("starts a serving process that changes as before once the key lifts", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				await p.upkeep.leaveMaintenance();
				const q = await harness.another(p, upkeepSpaces);
				expect((await q.store.putIfAbsent(fresh(), 1, never)).kind).toBe("written");
				expect(await q.upkeep.mark("test.after-lift", 1)).toEqual({ kind: "marked" });
			});

			it("refuses a declaration that is no object at all before reading it, naming store.declaration", async () => {
				const p = await harness.start(upkeepSpaces);
				const nothing = null as unknown as Space;
				await refusedSaying(harness.another(p, [none, nothing]), /store\.declaration/);
			});

			it("writes nothing when it refuses a start: the ledger keeps no space the refused process declared", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				await p.upkeep.require([held.name]);
				await p.upkeep.leaveMaintenance();
				const only: Space = { name: "upkeep-refused", guarantees: [], subjectData: "none" };
				await refusedAs(harness.another(p, [none, only]), lacking);
				expect((await p.upkeep.kept()).map((s) => s.name)).not.toContain(only.name);
			});
		});

		describe("the key's fence", () => {
			const tool = (p: UpkeepProcess, declared: readonly Space[]) =>
				harness.anotherMayBuildUnderKey(p, declared);
			/** Every change a process may try, each to be unavailable once its key has lifted. */
			const changes = (q: UpkeepProcess) => [
				() => q.upkeep.mark("test.fenced", 1),
				() => q.store.batch([], [{ key: fresh(), put: 1, ...never }]),
				...(q.store.batchAcross
					? [async () => q.store.batchAcross?.([], [{ key: fresh(), put: 1, ...never }])]
					: []),
				() => q.upkeep.sweep(none),
				() => q.upkeep.enterMaintenance(),
				() => q.upkeep.leaveMaintenance(),
				() => q.upkeep.require([none.name]),
				() => q.upkeep.retire("gone"),
			];

			it("answers what expired absent when a process behind the key's fence reads it, removing nothing, held where that can be seen", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				const k = fresh();
				await p.store.putIfAbsent(k, 1, { expiry: { kind: "after", ms: 20 } });
				await p.upkeep.leaveMaintenance();
				await sleep(40);
				expect((await p.store.get(k)).entry).toBeNull();
				if (p.store.getMany) expect((await p.store.getMany([k]))[0]?.entry).toBeNull();
				if (readsShowHeld) expect(await harness.holds?.(p, k)).toBe(true);
			});

			it("fences a process that started under the key once the key lifts", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				const t = await tool(p, upkeepSpaces);
				expect(await t.upkeep.mark("test.under", 1)).toEqual({ kind: "marked" });
				await t.upkeep.leaveMaintenance();
				for (const change of changes(t)) await expect(change()).rejects.toBeInstanceOf(Unavailable);
				expect((await t.control.control()).marks["test.fenced"]).toBeUndefined();
			});

			it("fences a process that entered the key once the key lifts, and a new one changes", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				const k = fresh();
				await p.store.putIfAbsent(k, 1, { expiry: { kind: "after", ms: 20 } });
				await p.upkeep.leaveMaintenance();
				await sleep(40);
				for (const change of changes(p)) await expect(change()).rejects.toBeInstanceOf(Unavailable);
				// Neither a change nor `sweep` behind the fence removes what expired, where it stays held.
				if (readsShowHeld) expect(await harness.holds?.(p, k)).toBe(true);
				const q = await harness.another(p, upkeepSpaces);
				expect(await q.upkeep.mark("test.after", 1)).toEqual({ kind: "marked" });
			});

			it("fences a tool another process lifts the key under, judged on the record at each change", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				const t = await tool(p, [none]);
				await p.upkeep.require([held.name]);
				await p.upkeep.leaveMaintenance();
				for (const change of changes(t)) await expect(change()).rejects.toBeInstanceOf(Unavailable);
				expect((await t.control.control()).marks["test.fenced"]).toBeUndefined();
			});

			it("fences an exempt tool that grows requires itself once it lifts the key", async () => {
				const p = await harness.start(upkeepSpaces);
				await p.upkeep.enterMaintenance();
				await p.upkeep.require([held.name]);
				const t = await tool(p, [none]);
				expect(await t.upkeep.require([held.name, plain.name])).toEqual({ kind: "required" });
				await t.upkeep.leaveMaintenance();
				for (const change of changes(t)) await expect(change()).rejects.toBeInstanceOf(Unavailable);
			});
		});

		describe("reading", () => {
			it("answers what expired absent when a process that may change reads it, removing nothing, held where that can be seen", async () => {
				const p = await harness.start(upkeepSpaces);
				const k = fresh();
				await p.store.putIfAbsent(k, 1, { expiry: { kind: "after", ms: 20 } });
				await sleep(40);
				expect((await p.store.get(k)).entry).toBeNull();
				if (p.store.getMany) expect((await p.store.getMany([k]))[0]?.entry).toBeNull();
				if (readsShowHeld) expect(await harness.holds?.(p, k)).toBe(true);
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

			it("checks a process's declarations before it writes the ledger: a malformed one marks no space", async () => {
				const p = await harness.start(upkeepSpaces);
				const bare = { name: "upkeep-bare", guarantees: [] } as unknown as Space;
				await refusedSaying(harness.another(p, [none, bare]), /declares no subjectData/);
				expect((await p.upkeep.kept()).map((s) => s.name)).not.toContain(bare.name);
			});

			it("never turns a space back to holding no subject's data", async () => {
				const p = await harness.start(upkeepSpaces);
				await harness.another(p, [{ ...none, subjectData: "online-keyed" }]);
				await harness.another(p, [none, { ...held, subjectData: "none" }]);
				const kept = new Map((await p.upkeep.kept()).map((s) => [s.name, s.subjectDataEver]));
				expect(kept.get(none.name)).toBe(true);
				expect(kept.get(held.name)).toBe(true);
			});

			it("keeps a space a process no longer declares, while its data stays, outside maintenance", async () => {
				const p = await harness.start(upkeepSpaces);
				const k = fresh(held);
				await plantValue(p.store, k, 1, never.expiry);
				const fewer = await harness.another(p, [none]);
				expect(await fewer.upkeep.retire(held.name)).toEqual({ kind: "not-in-maintenance" });
				expect((await p.upkeep.kept()).map((s) => s.name)).toContain(held.name);
				expect((await p.store.get(k)).entry?.value).toBe(1);
			});

			it("retires a space no longer declared under the maintenance key, never one the process declares", async () => {
				const p = await harness.start(upkeepSpaces);
				const fewer = await harness.another(p, [none]);
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
				expect(await p.upkeep.honours([])).toEqual({
					kind: "verified",
					witness: expect.any(String),
				});
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
				for (const k of keys) await plantValue(p.store, k, 1, never.expiry);
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

			it("takes back every cursor it gives, over keys of the longest names", async () => {
				const p = await harness.start(upkeepSpaces);
				const partition = `sweep${++n}`.padEnd(512, "p");
				for (let i = 0; i < 101; i++) {
					await plantValue(
						p.store,
						{ space: held, partition, name: `${i}`.padEnd(512, "k") },
						i,
						never.expiry,
					);
				}
				let seen = 0;
				let cursor: string | undefined;
				do {
					const page = await p.upkeep.sweep(held, cursor);
					seen += page.keys.filter((k) => k.partition === partition).length;
					cursor = page.cursor;
				} while (cursor !== undefined);
				expect(seen).toBe(101);
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
