import { defineModule, isUnavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { clientSection } from "./client-section.ts";
import type { section } from "./section.ts";
import {
	askStore,
	grantStore,
	type RecordStore,
	type StoredAsk,
	type StoredGrant,
} from "./store.ts";

export type ConsentSettings = z.input<typeof section>;

/** The consent part of a test's configuration, with its page at https://as.example/consent unless the test says otherwise. */
export function consentConfig(settings: Partial<ConsentSettings> = {}) {
	return { consent: { page: "https://as.example/consent", ...settings } };
}

/** The client metadata consent reads, for a test client. */
export function firstPartyFor(value: boolean) {
	return { [clientSection.name]: { "first-party": value } };
}

/** Records kept in memory, as `records`' stand-in makes them on the test's clock. */
export interface RecordsStandIn<T> {
	readonly records: {
		create: RecordStore<T>["save"];
		read: RecordStore<T>["read"];
		change: RecordStore<T>["update"];
	};
}

/** consent's store interfaces on two record stand-ins, for tests that assemble consent. */
export function consentStoresOn(stands: {
	readonly grants: RecordsStandIn<StoredGrant>;
	readonly asks: RecordsStandIn<StoredAsk>;
}) {
	const storeOf = <T>({ records }: RecordsStandIn<T>): RecordStore<T> => ({
		save: records.create,
		read: records.read,
		update: records.change,
	});
	return defineModule({ name: "consent-stores", takes: [] }, (m) => [
		m.provide(grantStore).by(() => storeOf(stands.grants)),
		m.provide(askStore).by(() => storeOf(stands.asks)),
	]);
}

/** A place that keeps one of consent's kinds of record, as one implementation of its store interfaces offers it. */
export interface ConsentPlace<T> {
	readonly records: RecordStore<T>;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `key` writes, another writer changes its record as given. */
	raceNextUpdate(key: string, change: (record: T) => T): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where the place replicates: while on, replicas take nothing, so nothing read can be confirmed. */
	readonly stallReplicas?: (on: boolean) => void;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

let n = 0;
/** A key no other test uses. */
const fresh = () => `k-${++n}-${Math.random().toString(36).slice(2)}`;

/**
 * What consent needs from any implementation of one of its store interfaces: records kept whole
 * and once, read back, changed only from what they hold, ended at exactly their lifetime or never,
 * through lost answers, restarts, memory pressure and failovers.
 */
function recordTests<T>(open: () => Promise<ConsentPlace<T>>): void {
	const held = (value: object) => value as unknown as T;
	const counted = (record: T) => (record as unknown as { n: number }).n;
	const plus = (record: T) => ({ value: held({ n: counted(record) + 1 }) });

	it("keeps a record whole and once per key, and reads it back", async () => {
		const { records } = await open();
		const key = fresh();
		const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
		expect(await records.save(key, odd, 60_000)).toBe("created");
		expect(await records.save(key, held({ n: 1 }), 60_000)).toBe("exists");
		expect(await records.read(key)).toEqual(odd);
		expect(await records.update(key, () => undefined)).toEqual({ before: odd, after: odd });
		expect(await records.read(fresh())).toBeUndefined();
		expect(await records.update(fresh(), plus)).toBeUndefined();
	});

	it("changes a record only from what it holds, again after a racing writer", async () => {
		const place = await open();
		const key = fresh();
		await place.records.save(key, held({ n: 1 }), 60_000);
		expect(await place.records.update(key, plus)).toEqual({
			before: held({ n: 1 }),
			after: held({ n: 2 }),
		});
		place.raceNextUpdate(key, (record) => held({ n: counted(record) * 10 }));
		expect(await place.records.update(key, plus)).toEqual({
			before: held({ n: 20 }),
			after: held({ n: 21 }),
		});
	});

	it("ends a record at exactly its lifetime, which a change keeps, or never", async () => {
		const place = await open();
		const [ending, endless] = [fresh(), fresh()];
		await place.records.save(ending, held({ n: 1 }), 1000);
		await place.records.save(endless, held({ n: 1 }), "endless");
		place.advance(999);
		await place.records.update(ending, plus);
		expect(await place.records.read(ending)).toEqual(held({ n: 2 }));
		place.advance(1);
		expect(await place.records.read(ending)).toBeUndefined();
		expect(await place.records.save(ending, held({ n: 3 }), 1000)).toBe("created");
		place.advance(10 * 365 * 86_400_000);
		expect(await place.records.read(endless)).toEqual(held({ n: 1 }));
	});

	it("keeps records through a restart and through memory pressure", async (context) => {
		const place = await open();
		const { restart, pressMemory } = place;
		if (!restart || !pressMemory) return context.skip();
		const key = fresh();
		await place.records.save(key, held({ n: 1 }), 60_000);
		await restart();
		await pressMemory();
		expect(await place.records.read(key)).toEqual(held({ n: 1 }));
	});

	it("settles writes whose answers were lost, and keeps them through a failover", async (context) => {
		const place = await open();
		const { loseNextAnswer: lose, failover } = place;
		if (!lose || !failover) return context.skip();
		const key = fresh();
		lose();
		expect(await place.records.save(key, held({ n: 1 }), 60_000)).toBe("created");
		lose();
		expect((await place.records.update(key, plus))?.after).toEqual(held({ n: 2 }));
		await failover();
		expect(await place.records.read(key)).toEqual(held({ n: 2 }));
	});
}

/** What consent needs from any implementation of its grant store: records whose reads are confirmed. */
export function grantStoreContract(
	name: string,
	open: () => Promise<ConsentPlace<StoredGrant>>,
): void {
	describe(`consent's grant store: ${name}`, () => {
		recordTests(open);

		it("reads only what is confirmed", async (context) => {
			const place = await open();
			const { stallReplicas: stall } = place;
			if (!stall) return context.skip();
			const key = fresh();
			await place.records.save(key, {} as StoredGrant, "endless");
			stall(true);
			await expect(place.records.read(key)).rejects.toSatisfy(isUnavailable);
			stall(false);
			expect(await place.records.read(key)).toEqual({});
		});
	});
}

/** What consent needs from any implementation of its ask store. */
export function askStoreContract(name: string, open: () => Promise<ConsentPlace<StoredAsk>>): void {
	describe(`consent's ask store: ${name}`, () => {
		recordTests(open);

		it("never gives an ask's key to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [key, kept] = [fresh(), fresh()];
			await place.records.save(key, { kept } as unknown as StoredAsk, 60_000);
			await place.records.read(key);
			await place.records.update(key, (record) => ({ value: record }));
			expect([holds(kept), holds(key)]).toEqual([true, false]);
		});
	});
}
