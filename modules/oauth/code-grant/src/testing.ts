import { isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type { CodeStore, StoredCode, VoidList } from "./store.ts";

export type CodeGrantSettings = z.input<typeof section>;

export function codeGrantConfig(settings: Partial<CodeGrantSettings> = {}) {
	return { "code-grant": { ...settings } };
}

/** A place that keeps code-grant's records and voids, as one implementation of its store interfaces offers it. */
export interface CodePlace {
	readonly codes: CodeStore;
	readonly voids: VoidList;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `name` writes, another writer changes its record as given. */
	raceNextUpdate(name: string, change: (record: StoredCode) => StoredCode): void;
	/** Names the void list keeps together, and how many it keeps before it refuses. */
	readonly crowd: { readonly limit: number; hashes(count: number): readonly string[] };
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/**
 * What code-grant needs from any implementation of its store interfaces: records kept whole and
 * once, changed only from what they hold, ended at exactly their lifetime, and voids kept until
 * done, through lost answers and failovers, never pushed out to make room.
 */
export function codeStoreContract(name: string, open: () => Promise<CodePlace>): void {
	let n = 0;
	const fresh = () => `code-${++n}-${Math.random().toString(36).slice(2)}`;
	const held = (value: object) => value as unknown as StoredCode;
	const counted = (record: StoredCode) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredCode) => ({
		value: held({ n: counted(record) + by }),
	});
	const listed = async (voids: VoidList) => {
		const found: string[] = [];
		await voids.each(async (name) => {
			found.push(name);
		});
		return found.sort();
	};

	describe(`code-grant's store interfaces: ${name}`, () => {
		it("names a code the same way every time, never as the code, and apart from another code", async () => {
			const { codes } = await open();
			const [code, other] = [fresh(), fresh()];
			expect(codes.nameOf(code)).toBe(codes.nameOf(code));
			expect([code, codes.nameOf(other)]).not.toContain(codes.nameOf(code));
		});

		it("never gives a code to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [code, kept] = [fresh(), fresh()];
			const name = place.codes.nameOf(code);
			await place.codes.save(name, held({ kept }), 60_000);
			await place.codes.update(name, (record) => ({ value: record }));
			await place.voids.add(name);
			expect([holds(kept), holds(name), holds(code)]).toEqual([true, true, false]);
		});

		it("keeps a record whole and once per name, whatever it holds", async () => {
			const { codes } = await open();
			const name = fresh();
			const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await codes.save(name, odd, 60_000)).toBe("created");
			expect(await codes.save(name, held({ n: 1 }), 60_000)).toBe("exists");
			expect(await codes.update(name, () => undefined)).toEqual({ before: odd, after: odd });
			expect(await codes.update(fresh(), plus(1))).toBeUndefined();
		});

		it("changes a record only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const name = fresh();
			await place.codes.save(name, held({ n: 1 }), 60_000);
			expect(await place.codes.update(name, plus(1))).toEqual({
				before: held({ n: 1 }),
				after: held({ n: 2 }),
			});
			place.raceNextUpdate(name, (record) => held({ n: counted(record) * 10 }));
			expect((await place.codes.update(name, plus(1)))?.after).toEqual(held({ n: 21 }));
		});

		it("ends a record at exactly its lifetime, counted from the write that last set one", async () => {
			const place = await open();
			const name = fresh();
			await place.codes.save(name, held({ n: 1 }), 1000);
			place.advance(999);
			await place.codes.update(name, (record) => ({ value: record, lifetimeMs: 1000 }));
			place.advance(999);
			expect(await place.codes.update(name, () => undefined)).toBeDefined();
			place.advance(1);
			expect(await place.codes.update(name, () => undefined)).toBeUndefined();
			expect(await place.codes.save(name, held({ n: 2 }), 1000)).toBe("created");
		});

		it("keeps voids until done, and a void whose handling failed", async () => {
			const { voids } = await open();
			const [failing, settled, handled] = [fresh(), fresh(), fresh()];
			for (const name of [failing, settled, handled]) await voids.add(name);
			const swept = await voids.each(async (name) => {
				if (name === failing) throw new Error("not yet");
				if (name === settled) await voids.done(name);
			});
			expect(swept.failed).toBe(1);
			expect(await listed(voids)).toEqual([failing, handled].sort());
		});

		it("refuses a void past a full place without pushing out one it keeps", async () => {
			const { voids, crowd } = await open();
			const [over, ...kept] = crowd.hashes(crowd.limit + 1);
			for (const name of kept) await voids.add(name);
			await expect(voids.add(over as string)).rejects.toSatisfy(isUnavailable);
			expect(await listed(voids)).toEqual([...kept].sort());
		}, 60_000);

		it("keeps records and voids through a restart and through memory pressure", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const [name, kept] = [fresh(), fresh()];
			await place.codes.save(name, held({ n: 1 }), 60_000);
			await place.voids.add(kept);
			await restart();
			await pressMemory();
			expect((await place.codes.update(name, () => undefined))?.after).toEqual(held({ n: 1 }));
			expect(await listed(place.voids)).toEqual([kept]);
		});

		// Each interface fails over after its own writes: a later write in another space would
		// confirm them, and hide a space that does not replicate.
		it("settles writes whose answers were lost, and keeps each interface's through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const [name, kept, settled] = [fresh(), fresh(), fresh()];
			lose();
			expect(await place.codes.save(name, held({ n: 1 }), 60_000)).toBe("created");
			lose();
			expect((await place.codes.update(name, plus(1)))?.after).toEqual(held({ n: 2 }));
			await failover();
			expect((await place.codes.update(name, () => undefined))?.after).toEqual(held({ n: 2 }));
			lose();
			await place.voids.add(kept);
			await place.voids.add(settled);
			lose();
			await place.voids.done(settled);
			await failover();
			expect(await listed(place.voids)).toEqual([kept]);
		});
	});
}
