import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type { RefreshLocks, StoredUpstreamTokens, UpstreamTokenStore } from "./store.ts";

export type FederationTokensSettings = z.input<typeof section>;

export function federationTokensConfig(settings: Partial<FederationTokensSettings> = {}) {
	return { "federation-tokens": settings };
}

/** A place that keeps federation-tokens' records and locks, as one implementation of its store interfaces offers it. */
export interface UpstreamTokenPlace {
	readonly records: UpstreamTokenStore;
	readonly locks: RefreshLocks;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `session` writes, another writer changes its record as given. */
	raceNextUpdate(
		session: string,
		change: (record: StoredUpstreamTokens) => StoredUpstreamTokens,
	): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
}

/**
 * What federation-tokens needs from any implementation of its store interfaces: a session's
 * record kept whole, changed only from what it holds, ended at its lifetime, kept through a
 * failover once answered; and a lock held by one taker until released or ended.
 */
export function upstreamTokenStoreContract(
	name: string,
	open: () => Promise<UpstreamTokenPlace>,
): void {
	let n = 0;
	const fresh = () => `s-${++n}-${Math.random().toString(36).slice(2)}`;
	const held = (value: object) => value as unknown as StoredUpstreamTokens;
	const counted = (record: StoredUpstreamTokens) => (record as unknown as { n: number }).n;
	const plus = (record: StoredUpstreamTokens) => ({
		value: held({ n: counted(record) + 1 }),
		lifetimeMs: 60_000,
	});

	describe(`federation-tokens' store interfaces: ${name}`, () => {
		it("keeps a session's record whole and once, and removes it", async () => {
			const { records } = await open();
			const [key, other] = [fresh(), fresh()];
			const odd = held({ idps: { corp: { version: "v", sealed: "x" } }, list: [1, "two"] });
			expect(await records.save(key, odd, 60_000)).toBe("created");
			expect(await records.save(key, held({ n: 1 }), 60_000)).toBe("exists");
			await records.save(other, held({ n: 2 }), 60_000);
			expect(await records.read(key)).toEqual(odd);
			await records.remove(key);
			await records.remove(fresh());
			expect(await records.read(key)).toBeUndefined();
			expect(await records.read(other)).toEqual(held({ n: 2 }));
		});

		it("changes a record only from what it holds, and nothing that is gone", async () => {
			const place = await open();
			const key = fresh();
			expect(await place.records.update(key, plus)).toBeUndefined();
			await place.records.save(key, held({ n: 1 }), 60_000);
			place.raceNextUpdate(key, (record) => held({ n: counted(record) * 10 }));
			expect(await place.records.update(key, plus)).toEqual({
				before: held({ n: 10 }),
				after: held({ n: 11 }),
			});
		});

		it("ends a record at its lifetime, which a change renews", async () => {
			const place = await open();
			const key = fresh();
			await place.records.save(key, held({ n: 1 }), 1000);
			place.advance(999);
			await place.records.update(key, (record) => ({ value: record, lifetimeMs: 1000 }));
			place.advance(999);
			expect(await place.records.read(key)).toBeDefined();
			place.advance(1);
			expect(await place.records.read(key)).toBeUndefined();
		});

		it("keeps a record's lifetime through a change that names none", async () => {
			const place = await open();
			const key = fresh();
			await place.records.save(key, held({ n: 1 }), 1000);
			place.advance(500);
			await place.records.update(key, (record) => ({ value: held({ n: counted(record) + 1 }) }));
			place.advance(499);
			expect(await place.records.read(key)).toEqual(held({ n: 2 }));
			place.advance(1);
			expect(await place.records.read(key)).toBeUndefined();
		});

		it("walks the sessions whose records live, over pages", async () => {
			const place = await open();
			const keys = Array.from({ length: 120 }, fresh);
			for (const key of keys) await place.records.save(key, held({ n: 1 }), 60_000);
			await place.records.remove(keys[0] as string);
			const seen = new Set<string>();
			let cursor: string | undefined;
			do {
				const page = await place.records.scan(cursor);
				for (const session of page.keys) seen.add(session);
				cursor = page.cursor;
			} while (cursor !== undefined);
			expect(keys.filter((key) => !seen.has(key))).toEqual([keys[0]]);
		});

		it("holds a lock under one mark, and changes it only from the mark it holds now", async () => {
			const place = await open();
			const { hold, update } = place.locks;
			const lock = fresh();
			const endIf = (mark: string) => (held: string) =>
				held === mark ? { value: held, lifetimeMs: 1 } : undefined;
			expect(await hold.call(place.locks, lock, "a", 1000)).toBe("created");
			expect(await hold.call(place.locks, lock, "b", 1000)).toBe("exists");
			place.advance(1000);
			expect(await hold.call(place.locks, lock, "b", 1000)).toBe("created");
			await update.call(place.locks, lock, endIf("a"));
			place.advance(1);
			expect(await hold.call(place.locks, lock, "c", 1000)).toBe("exists");
			await update.call(place.locks, lock, endIf("b"));
			place.advance(1);
			expect(await hold.call(place.locks, lock, "c", 1000)).toBe("created");
		});

		it("keeps a change whose answer was lost, through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			await place.records.save(key, held({ n: 1 }), 60_000);
			lose();
			expect((await place.records.update(key, plus))?.after).toEqual(held({ n: 2 }));
			await failover();
			expect(await place.records.read(key)).toEqual(held({ n: 2 }));
		});
	});
}
