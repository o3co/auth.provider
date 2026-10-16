import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type {
	FamilyStore,
	MemberLists,
	RedemptionStore,
	SettleList,
	StoredFamily,
	StoredLink,
	StoredRedemption,
	TokenFamilies,
} from "./store.ts";

export type RefreshSettings = z.input<typeof section>;

export function refreshConfig(settings: Partial<RefreshSettings> = {}) {
	return { refresh: { ...settings } };
}

/** A place that keeps refresh's records and lists, as one implementation of its store interfaces offers it. */
export interface RefreshStorePlace {
	readonly families: FamilyStore;
	readonly redemptions: RedemptionStore;
	readonly sessionFamilies: MemberLists;
	readonly issuedAccess: MemberLists;
	readonly tokenFamilies: TokenFamilies;
	readonly settles: SettleList;
	/** How many members each list keeps to a key. */
	readonly caps: { readonly sessionFamilies: number; readonly issuedAccess: number };
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `id` writes, another writer changes its record as given. */
	raceNextUpdate(id: string, change: (record: StoredFamily) => StoredFamily): void;
	/** Families the settle list keeps together, and how many it keeps before it refuses. */
	readonly crowd: { readonly limit: number; ids(count: number): readonly string[] };
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/**
 * What refresh needs from any implementation of its store interfaces: records kept whole and
 * once, changed only from what they hold, ended at exactly their lifetime; lists capped by
 * pushing out the first to end; settles kept until done, through lost answers and failovers.
 */
export function refreshStoreContract(name: string, open: () => Promise<RefreshStorePlace>): void {
	let n = 0;
	const fresh = () => `r-${++n}-${Math.random().toString(36).slice(2)}`;
	const held = (value: object) => value as unknown as StoredFamily;
	const marked = (value: object) => value as unknown as StoredRedemption;
	const linked = (value: object) => value as unknown as StoredLink;
	const counted = (record: StoredFamily) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredFamily) => ({
		value: held({ n: counted(record) + by }),
	});
	const listed = async (settles: SettleList) => {
		const found: string[] = [];
		await settles.each(async (id) => {
			found.push(id);
		});
		return found.sort();
	};
	const names = async (lists: MemberLists, key: string) =>
		(await lists.members(key)).map((m) => m.member).sort();
	/** What a list does up to and past its cap, on a clock the test moves. */
	const capped = async (place: RefreshStorePlace, lists: MemberLists, cap: number) => {
		const key = fresh();
		expect((await lists.add(key, "b", 3000)).pushedOut).toEqual([]);
		expect((await lists.add(key, "a", 1000)).pushedOut).toEqual([]);
		expect((await lists.add(key, "a", 500)).pushedOut).toEqual([]);
		expect(await lists.members(key)).toEqual([
			{ member: "a", remainingMs: 1000 },
			{ member: "b", remainingMs: 3000 },
		]);
		for (let i = 2; i < cap; i++) await lists.add(key, `m-${i}`, 5000);
		expect((await lists.add(key, "late", 4000)).pushedOut).toEqual(["a"]);
		expect(await names(lists, fresh())).toEqual([]);
		place.advance(3000);
		expect(await names(lists, key)).not.toContain("b");
		expect(await names(lists, key)).toContain("late");
	};

	describe(`refresh's store interfaces: ${name}`, () => {
		it("keeps a family whole and once per name, whatever it holds", async () => {
			const { families } = await open();
			const id = fresh();
			const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await families.save(id, odd, 60_000)).toBe("created");
			expect(await families.save(id, held({ n: 1 }), 60_000)).toBe("exists");
			expect(await families.read(id)).toEqual(odd);
			expect(await families.update(id, () => undefined)).toEqual({ before: odd, after: odd });
			expect(await families.update(fresh(), plus(1))).toBeUndefined();
			expect(await families.read(fresh())).toBeUndefined();
		});

		it("changes a family only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const id = fresh();
			await place.families.save(id, held({ n: 1 }), 60_000);
			expect(await place.families.update(id, plus(1))).toEqual({
				before: held({ n: 1 }),
				after: held({ n: 2 }),
			});
			place.raceNextUpdate(id, (record) => held({ n: counted(record) * 10 }));
			expect((await place.families.update(id, plus(1)))?.after).toEqual(held({ n: 21 }));
		});

		it("ends a family at exactly its lifetime, counted from the write that last set one", async () => {
			const place = await open();
			const id = fresh();
			await place.families.save(id, held({ n: 1 }), 1000);
			place.advance(999);
			await place.families.update(id, (record) => ({ value: record, lifetimeMs: 1000 }));
			place.advance(999);
			expect(await place.families.read(id)).toBeDefined();
			place.advance(1);
			expect(await place.families.read(id)).toBeUndefined();
			expect(await place.families.save(id, held({ n: 2 }), 1000)).toBe("created");
		});

		it("keeps what a redemption left once, for its lifetime", async () => {
			const place = await open();
			const key = fresh();
			expect(await place.redemptions.save(key, marked({ family: "f" }), 1000)).toBe("created");
			expect(await place.redemptions.save(key, marked({ taken: true }), 1000)).toBe("exists");
			expect(await place.redemptions.read(key)).toEqual(marked({ family: "f" }));
			place.advance(1000);
			expect(await place.redemptions.read(key)).toBeUndefined();
		});

		it("keeps the family of a token once, for its lifetime", async () => {
			const place = await open();
			const id = fresh();
			expect(await place.tokenFamilies.save(id, linked({ family: "f" }), 1000)).toBe("created");
			expect(await place.tokenFamilies.save(id, linked({ family: "g" }), 1000)).toBe("exists");
			expect(await place.tokenFamilies.read(id)).toEqual(linked({ family: "f" }));
			place.advance(999);
			expect(await place.tokenFamilies.read(id)).toBeDefined();
			place.advance(1);
			expect(await place.tokenFamilies.read(id)).toBeUndefined();
		});

		it("keeps each list's members for their lifetimes, pushing out the first to end past its cap", async () => {
			const place = await open();
			await capped(place, place.sessionFamilies, place.caps.sessionFamilies);
			await capped(place, place.issuedAccess, place.caps.issuedAccess);
		}, 60_000);

		it("keeps settles until done, and a settle whose handling failed", async () => {
			const { settles } = await open();
			const [failing, settled, handled] = [fresh(), fresh(), fresh()];
			for (const id of [failing, settled, handled]) await settles.add(id);
			const swept = await settles.each(async (id) => {
				if (id === failing) throw new Error("not yet");
				if (id === settled) await settles.done(id);
			});
			expect(swept.failed).toBe(1);
			expect(await listed(settles)).toEqual([failing, handled].sort());
		});

		it("refuses a settle past a full place without pushing out one it keeps", async () => {
			const { settles, crowd } = await open();
			const [over, ...kept] = crowd.ids(crowd.limit + 1);
			for (const id of kept) await settles.add(id);
			await expect(settles.add(over as string)).rejects.toSatisfy(isUnavailable);
			expect(await listed(settles)).toEqual([...kept].sort());
		}, 60_000);

		it("keeps records, lists and settles through a restart and through memory pressure", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const [id, key, kept] = [fresh(), fresh(), fresh()];
			await place.families.save(id, held({ n: 1 }), 60_000);
			await place.redemptions.save(key, marked({ family: id }), 60_000);
			await place.sessionFamilies.add(key, id, 60_000);
			await place.issuedAccess.add(id, key, 60_000);
			await place.tokenFamilies.save(key, linked({ family: id }), 60_000);
			await place.settles.add(kept);
			await restart();
			await pressMemory();
			expect(await place.families.read(id)).toEqual(held({ n: 1 }));
			expect(await place.redemptions.read(key)).toEqual(marked({ family: id }));
			expect(await names(place.sessionFamilies, key)).toEqual([id]);
			expect(await names(place.issuedAccess, id)).toEqual([key]);
			expect(await place.tokenFamilies.read(key)).toEqual(linked({ family: id }));
			expect(await listed(place.settles)).toEqual([kept]);
		});

		// Each interface fails over after its own writes: a later write in another space would
		// confirm them, and hide a space that does not replicate.
		it("settles writes whose answers were lost, and keeps each interface's through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const [id, key, kept, settled] = [fresh(), fresh(), fresh(), fresh()];
			lose();
			expect(await place.families.save(id, held({ n: 1 }), 60_000)).toBe("created");
			lose();
			expect((await place.families.update(id, plus(1)))?.after).toEqual(held({ n: 2 }));
			await failover();
			expect(await place.families.read(id)).toEqual(held({ n: 2 }));
			lose();
			expect(await place.redemptions.save(key, marked({ family: id }), 60_000)).toBe("created");
			await failover();
			expect(await place.redemptions.read(key)).toEqual(marked({ family: id }));
			lose();
			expect((await place.sessionFamilies.add(key, id, 60_000)).pushedOut).toEqual([]);
			await failover();
			expect(await names(place.sessionFamilies, key)).toEqual([id]);
			lose();
			expect((await place.issuedAccess.add(id, key, 60_000)).pushedOut).toEqual([]);
			await failover();
			expect(await names(place.issuedAccess, id)).toEqual([key]);
			lose();
			expect(await place.tokenFamilies.save(key, linked({ family: id }), 60_000)).toBe("created");
			await failover();
			expect(await place.tokenFamilies.read(key)).toEqual(linked({ family: id }));
			lose();
			await place.settles.add(kept);
			await place.settles.add(settled);
			lose();
			await place.settles.done(settled);
			await failover();
			expect(await listed(place.settles)).toEqual([kept]);
		});
	});
}
