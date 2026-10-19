import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type { ReauthStore, StoredReauth } from "./store.ts";

export type AuthorizeSettings = z.input<typeof section>;

export function authorizeConfig(settings: Partial<AuthorizeSettings> = {}) {
	return { authorize: { "login-page": "https://as.example/login", ...settings } };
}

/** A place that keeps authorize's re-authentications, as one implementation of its store interface offers it. */
export interface ReauthPlace {
	readonly reauths: ReauthStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `name` writes, another writer changes its record as given. */
	raceNextUpdate(name: string, change: (record: StoredReauth) => StoredReauth): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/**
 * What authorize needs from any implementation of its store interface: records kept whole and
 * once, changed only from what they hold, ended at exactly their lifetime, through lost answers,
 * restarts and failovers.
 */
export function reauthStoreContract(name: string, open: () => Promise<ReauthPlace>): void {
	let n = 0;
	const fresh = () => `a-${++n}-${Math.random().toString(36).slice(2)}`;
	const held = (value: object) => value as unknown as StoredReauth;
	const counted = (record: StoredReauth) => (record as unknown as { n: number }).n;
	const plus = (record: StoredReauth) => ({ value: held({ n: counted(record) + 1 }) });
	const read = async (reauths: ReauthStore, key: string) =>
		(await reauths.update(key, () => undefined))?.after;

	describe(`authorize's store interface: ${name}`, () => {
		it("keeps a record whole and once per name, and changes it only from what it holds", async () => {
			const place = await open();
			const key = fresh();
			const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await place.reauths.save(key, odd, 60_000)).toBe("created");
			expect(await place.reauths.save(key, held({ n: 1 }), 60_000)).toBe("exists");
			expect(await read(place.reauths, key)).toEqual(odd);
			expect(await place.reauths.update(fresh(), plus)).toBeUndefined();
			const counting = fresh();
			await place.reauths.save(counting, held({ n: 1 }), 60_000);
			place.raceNextUpdate(counting, (record) => held({ n: counted(record) * 10 }));
			expect(await place.reauths.update(counting, plus)).toEqual({
				before: held({ n: 10 }),
				after: held({ n: 11 }),
			});
		});

		it("never gives a re-authentication's name to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [key, kept] = [fresh(), fresh()];
			await place.reauths.save(key, held({ kept }), 60_000);
			await place.reauths.update(key, (record) => ({ value: record }));
			expect([holds(kept), holds(key)]).toEqual([true, false]);
		});

		it("ends a record at exactly its lifetime", async () => {
			const place = await open();
			const key = fresh();
			await place.reauths.save(key, held({ n: 1 }), 1000);
			place.advance(999);
			expect(await read(place.reauths, key)).toBeDefined();
			place.advance(1);
			expect(await read(place.reauths, key)).toBeUndefined();
		});

		it("keeps records through a restart, and writes whose answers were lost through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart } = place;
			if (!lose || !failover || !restart) return context.skip();
			const key = fresh();
			lose();
			expect(await place.reauths.save(key, held({ n: 1 }), 60_000)).toBe("created");
			lose();
			expect((await place.reauths.update(key, plus))?.after).toEqual(held({ n: 2 }));
			await failover();
			await restart();
			expect(await read(place.reauths, key)).toEqual(held({ n: 2 }));
		});
	});
}
