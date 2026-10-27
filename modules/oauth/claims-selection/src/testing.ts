import { type Clock, defineModule, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { Settings } from "./section.ts";
import {
	type ConstrainedFamilyList,
	constrainedFamilyList,
	type SelectionRecords,
	type StoredSelection,
	selectionRecords,
} from "./store.ts";

/** A place that keeps selections, as one implementation of the store interface offers it. */
export interface RecordsPlace {
	readonly records: SelectionRecords;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

const value = (n: number) => ({ format: 1, n }) as unknown as StoredSelection;

/** What claims-selection needs from any implementation: each record kept once, for exactly its lifetime, through faults. */
export function selectionRecordsContract(name: string, open: () => Promise<RecordsPlace>): void {
	let n = 0;
	const fresh = () => `r-${++n}-${Math.random().toString(36).slice(2)}`;
	describe(`claims-selection's store interface: ${name}`, () => {
		it("keeps the first record saved under a name for exactly its lifetime", async () => {
			const place = await open();
			const [kept, other] = [fresh(), fresh()];
			expect(await place.records.save(kept, value(1), 1000)).toBe("created");
			expect(await place.records.save(kept, value(2), 5000)).toBe("exists");
			expect(await place.records.read(kept)).toEqual(value(1));
			expect(await place.records.read(other)).toBeUndefined();
			place.advance(999);
			expect(await place.records.read(kept)).toEqual(value(1));
			place.advance(1);
			expect(await place.records.read(kept)).toBeUndefined();
		});

		it("keeps records through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, settled] = [fresh(), fresh()];
			await place.records.save(kept, value(1), 60_000);
			lose();
			expect(await place.records.save(settled, value(2), 60_000)).toBe("created");
			await failover();
			await restart();
			await pressMemory();
			expect(await place.records.read(kept)).toEqual(value(1));
			expect(await place.records.read(settled)).toEqual(value(2));
		});
	});
}

/** A place that keeps the constrained families' list, as one implementation of the store interface offers it. */
export interface ListPlace {
	readonly list: ConstrainedFamilyList;
	readonly loseNextAnswer?: () => void;
	readonly failover?: () => Promise<void>;
	readonly restart?: () => Promise<void>;
	readonly pressMemory?: () => Promise<void>;
}

/** What claims-selection needs of the constrained families' list: each family listed once until done, through faults. */
export function constrainedFamilyListContract(name: string, open: () => Promise<ListPlace>): void {
	let n = 0;
	const fresh = () => `fam-${++n}-${Math.random().toString(36).slice(2)}`;
	const listed = async (list: ConstrainedFamilyList) => {
		const seen: string[] = [];
		await list.each(async (id) => {
			seen.push(id);
		});
		return seen;
	};
	describe(`claims-selection's constrained families: ${name}`, () => {
		it("lists a family once however often, hands each listed one, and keeps one whose handling fails", async () => {
			const { list } = await open();
			const [kept, failing, gone] = [fresh(), fresh(), fresh()];
			for (const id of [kept, kept, failing, gone]) await list.add(id);
			await list.done(gone);
			const seen = await listed(list);
			expect(seen.filter((id) => id === kept)).toHaveLength(1);
			expect(seen).toContain(failing);
			expect(seen).not.toContain(gone);
			const { failed } = await list.each(async (id) => {
				if (id === failing) throw new Error("not handled");
			});
			expect(failed).toBe(1);
			expect(await listed(list)).toContain(failing);
		});

		it("keeps what it lists through restarts, memory pressure, lost answers and failovers", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [kept, settled] = [fresh(), fresh()];
			await place.list.add(kept);
			lose();
			await place.list.add(settled);
			await failover();
			await restart();
			await pressMemory();
			expect(await listed(place.list)).toEqual(expect.arrayContaining([kept, settled]));
		});
	});
}

/**
 * claims-selection's store in memory, on the composition's clock, for tests that compose the module;
 * `around` and `aroundList` wrap what the composition is given, as a test that fails or watches it
 * does, and the list holds `listCap` families at most.
 */
export function claimsSelectionInMemory(
	options: {
		readonly around?: (records: SelectionRecords) => SelectionRecords;
		readonly aroundList?: (list: ConstrainedFamilyList) => ConstrainedFamilyList;
		readonly listCap?: number;
	} = {},
) {
	let now = () => 0;
	const entries = new Map<string, { readonly value: StoredSelection; readonly ends: number }>();
	const live = (name: string) => {
		const found = entries.get(name);
		return found && found.ends > now() ? found : undefined;
	};
	const records: SelectionRecords = {
		save: async (name, kept, lifetimeMs) => {
			if (live(name)) return "exists";
			entries.set(name, { value: kept, ends: now() + lifetimeMs });
			return "created";
		},
		read: async (name) => live(name)?.value,
	};
	const listed = new Set<string>();
	const list: ConstrainedFamilyList = {
		add: async (id) => {
			if (!listed.has(id) && listed.size >= (options.listCap ?? 100_000))
				throw new Unavailable("claims-selection stand-in");
			listed.add(id);
		},
		done: async (id) => {
			listed.delete(id);
		},
		each: async (handle) => {
			let failed = 0;
			for (const id of [...listed]) await handle(id).catch(() => failed++);
			return { failed };
		},
	};
	const module = defineModule({ name: "claims-selection-stores", takes: [] }, (m) => [
		m.provide(selectionRecords).by((c: { readonly clock: Clock }) => {
			now = c.clock.now;
			return options.around ? options.around(records) : records;
		}),
		m
			.provide(constrainedFamilyList)
			.by(() => (options.aroundList ? options.aroundList(list) : list)),
	]);
	/** Writes a record over whatever the name holds, as a broken or foreign writer might. */
	const overwrite = (name: string, kept: unknown) => {
		entries.set(name, { value: kept as StoredSelection, ends: now() + 60_000 });
	};
	return {
		module,
		records,
		list,
		overwrite,
		names: () => [...entries.keys()].filter((k) => live(k)),
		listed: () => [...listed],
	};
}

/** claims-selection's section, as a configuration gives it: `on` unless `settings` says otherwise. */
export function claimsSelectionConfig(settings: Partial<Settings> = {}) {
	return { "claims-selection": { mode: "on", ...settings } };
}
