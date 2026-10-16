import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type {
	GrantStore,
	PendingIntents,
	RefreshLockStore,
	StepStore,
	StoredGrant,
	StoredStep,
	SubjectGrants,
} from "./store.ts";

export type FederationGrantsSettings = z.input<typeof section>;

export function federationGrantsConfig(settings: Partial<FederationGrantsSettings> = {}) {
	return { "federation-grants": settings };
}

/** A place that keeps federation-grants' records, as one implementation of its store interfaces offers it. */
export interface GrantPlace {
	readonly grants: GrantStore;
	readonly steps: StepStore;
	readonly pending: PendingIntents;
	readonly subjects: SubjectGrants;
	/** How many grants the pending set keeps to a pair. */
	readonly cap: number;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next change of grant `id` writes, another writer changes it as given. */
	raceNextChange(id: string, change: (record: StoredGrant) => StoredGrant): void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where reads can meet unconfirmed writes: runs `during` as the next grant's create takes effect, unconfirmed. */
	readonly duringNextCreate?: (during: () => Promise<void>) => void;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/**
 * What federation-grants needs from any implementation of its store interfaces: grants and steps
 * kept whole and once, changed only from what they hold, ended at their lifetime; steps under a
 * name the secret cannot be read from; and pending sets that push out the first to end over the cap.
 */
export function grantStoreContract(name: string, open: () => Promise<GrantPlace>): void {
	let n = 0;
	const fresh = () => `g-${++n}-${Math.random().toString(36).slice(2)}`;
	const grant = (value: object) => value as unknown as StoredGrant;
	const step = (value: object) => value as unknown as StoredStep;
	const counted = (record: StoredGrant) => (record as unknown as { n: number }).n;

	describe(`federation-grants' store interfaces: ${name}`, () => {
		it("keeps a grant whole and once, and changes it only from what it holds", async () => {
			const place = await open();
			const id = fresh();
			const odd = grant({ status: "active", nested: { list: [1, "two"] } });
			expect(await place.grants.create(id, odd, 60_000)).toBe("created");
			expect(await place.grants.create(id, grant({ n: 1 }), 60_000)).toBe("exists");
			expect(await place.grants.read(id)).toEqual(odd);
			expect(await place.grants.change(fresh(), (r) => ({ value: r }))).toBeUndefined();
			const other = fresh();
			await place.grants.create(other, grant({ n: 1 }), 60_000);
			place.raceNextChange(other, (r) => grant({ n: counted(r) * 10 }));
			const changed = await place.grants.change(other, (r) => ({
				value: grant({ n: counted(r) + 1 }),
			}));
			expect(changed?.after).toEqual(grant({ n: 11 }));
		});

		it("ends a grant at its lifetime, which a change with a lifetime renews", async () => {
			const place = await open();
			const id = fresh();
			await place.grants.create(id, grant({ n: 1 }), 1000);
			place.advance(999);
			await place.grants.change(id, () => ({ value: grant({ n: 2 }), lifetimeMs: 1000 }));
			place.advance(999);
			expect(await place.grants.read(id)).toBeDefined();
			place.advance(1);
			expect(await place.grants.read(id)).toBeUndefined();
		});

		it("keeps a step by its secret, which the place never holds in clear", async () => {
			const place = await open();
			const secret = `s3cr3t-${fresh()}`;
			expect(await place.steps.create(secret, step({ taken: false }), 60_000)).toBe("created");
			expect(await place.steps.read(secret)).toEqual(step({ taken: false }));
			await place.steps.change(secret, () => ({ value: step({ taken: true }) }));
			expect(await place.steps.read(secret)).toEqual(step({ taken: true }));
			expect(await place.steps.read(`${secret}x`)).toBeUndefined();
			if (place.holds) expect(place.holds(secret)).toBe(false);
		});

		it("pushes out the grant that ends first once a pair holds more than the cap", async () => {
			const place = await open();
			const pair = fresh();
			for (let i = 0; i < place.cap; i++) {
				expect((await place.pending.add(pair, `m-${i}`, 60_000 + i)).pushedOut).toEqual([]);
			}
			expect((await place.pending.add(pair, "late", 120_000)).pushedOut).toEqual(["m-0"]);
			await place.pending.remove(pair, "late");
			expect((await place.pending.add(pair, "again", 120_000)).pushedOut).toEqual([]);
		});

		it("lists a subject's grants each for its lifetime, until one is removed", async () => {
			const { subjects, advance } = await open();
			const [subject, other, ending, lasting] = [fresh(), fresh(), fresh(), fresh()];
			const members = async (of: string) =>
				(await subjects.members(of)).map(({ member }) => member).sort();
			expect((await subjects.add(subject, ending, 1000)).pushedOut).toEqual([]);
			await subjects.add(subject, lasting, 60_000);
			await subjects.add(other, ending, 60_000);
			expect(await members(subject)).toEqual([ending, lasting].sort());
			advance(1000);
			expect(await members(subject)).toEqual([lasting]);
			await subjects.remove(subject, lasting);
			await subjects.remove(fresh(), lasting);
			expect(await members(subject)).toEqual([]);
			expect(await members(other)).toEqual([ending]);
		});

		it("keeps grants, steps, pending sets and listings through memory pressure, and grants and listings through a restart", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const [id, secret, pair, subject] = [fresh(), fresh(), fresh(), fresh()];
			await place.grants.create(id, grant({ n: 1 }), 60_000);
			await place.steps.create(secret, step({ n: 1 }), 60_000);
			for (let i = 0; i < place.cap; i++) await place.pending.add(pair, `m-${i}`, 60_000 + i);
			await place.subjects.add(subject, id, 60_000);
			await pressMemory();
			expect(await place.grants.read(id)).toEqual(grant({ n: 1 }));
			expect(await place.steps.read(secret)).toEqual(step({ n: 1 }));
			expect((await place.pending.add(pair, "late", 120_000)).pushedOut).toEqual(["m-0"]);
			expect(await place.subjects.members(subject)).toMatchObject([{ member: id }]);
			await restart();
			expect(await place.grants.read(id)).toEqual(grant({ n: 1 }));
			expect(await place.subjects.members(subject)).toMatchObject([{ member: id }]);
		});

		// Each interface fails over after its own writes: a later write in another space would
		// confirm them, and hide a space that does not replicate.
		it("keeps confirmed grants, steps and listings through a failover", async (context) => {
			const place = await open();
			const { failover } = place;
			if (!failover) return context.skip();
			const [id, secret, subject] = [fresh(), fresh(), fresh()];
			await place.grants.create(id, grant({ n: 1 }), 60_000);
			await place.grants.change(id, () => ({ value: grant({ n: 2 }) }));
			await failover();
			expect(await place.grants.read(id)).toEqual(grant({ n: 2 }));
			await place.steps.create(secret, step({ n: 1 }), 60_000);
			await place.steps.change(secret, () => ({ value: step({ n: 2 }) }));
			await failover();
			expect(await place.steps.read(secret)).toEqual(step({ n: 2 }));
			await place.subjects.add(subject, id, 60_000);
			await failover();
			expect(await place.subjects.members(subject)).toMatchObject([{ member: id }]);
		});

		it("reads a grant another request wrote only as a failover keeps it", async (context) => {
			const place = await open();
			const { duringNextCreate, failover } = place;
			if (!duringNextCreate || !failover) return context.skip();
			const id = fresh();
			let seen: StoredGrant | undefined;
			duringNextCreate(async () => {
				seen = await place.grants.read(id);
				await failover();
				// Past any resend of the create, so only what the read confirmed is left.
				place.advance(60_000);
			});
			await place.grants.create(id, grant({ n: 1 }), 600_000).catch(() => undefined);
			expect(seen).toEqual(grant({ n: 1 }));
			expect(await place.grants.read(id)).toEqual(seen);
		});
	});
}

/** A place that keeps refresh locks under their holders' marks. */
export interface LockPlace {
	readonly locks: RefreshLockStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/** What any refresh lock store must do: one holder at a time, changed only from the mark it holds now. */
export function refreshLockStoreContract(name: string, open: () => Promise<LockPlace>): void {
	let n = 0;
	const fresh = () => `l-${++n}-${Math.random().toString(36).slice(2)}`;
	const endIf = (mark: string) => (held: string) =>
		held === mark ? { value: held, lifetimeMs: 1 } : undefined;

	describe(`federation-grants' refresh lock store: ${name}`, () => {
		it("holds a lock under one mark, and changes it only from the mark it holds now", async () => {
			const place = await open();
			const lock = fresh();
			expect(await place.locks.hold(lock, "a", 1000)).toBe("created");
			expect(await place.locks.hold(lock, "b", 1000)).toBe("exists");
			place.advance(1000);
			expect(await place.locks.hold(lock, "b", 1000)).toBe("created");
			await place.locks.update(lock, endIf("a"));
			place.advance(1);
			expect(await place.locks.hold(lock, "c", 1000)).toBe("exists");
			await place.locks.update(lock, endIf("b"));
			place.advance(1);
			expect(await place.locks.hold(lock, "c", 1000)).toBe("created");
		});

		it("changes nothing where no lock is held", async () => {
			const place = await open();
			const lock = fresh();
			expect(await place.locks.update(lock, endIf("a"))).toBeUndefined();
			expect(await place.locks.hold(lock, "a", 1000)).toBe("created");
		});

		it("keeps a held lock through memory pressure", async (context) => {
			const place = await open();
			const { pressMemory } = place;
			if (!pressMemory) return context.skip();
			const lock = fresh();
			await place.locks.hold(lock, "a", 60_000);
			await pressMemory();
			expect(await place.locks.hold(lock, "b", 60_000)).toBe("exists");
		});
	});
}
