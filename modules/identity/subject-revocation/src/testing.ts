import { randomUUID } from "node:crypto";
import { contract, defineModule } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	type Boundaries,
	comparedTo,
	recorded,
	subjectRevocationOf,
} from "./boundaries/boundaries.ts";
import {
	type ErasedSubjects,
	erasedSubjects,
	type Revocations,
	revocationFollowers,
	revocations,
	type SubjectErasure,
	type SubjectRevocation,
	subjectErasure,
	subjectRevocation,
} from "./contract.ts";
import { followedBy, type Write } from "./followers.ts";
import type { BoundaryStore, BoundaryWrite, StoredBoundary, StoredReceipt } from "./store.ts";

/** A composition that offers subject revocation, as one implementation of the contract does. */
export interface RevocationComposition {
	readonly revocation: SubjectRevocation;
	readonly revocations: Revocations;
	/** Marks a subject erased, as account erasure will. */
	readonly erasure: SubjectErasure;
	/** Whether a subject is marked erased. */
	readonly erasedSubjects: ErasedSubjects;
	/** The time a revocation now takes. */
	now(): number;
	/** Moves that time on. */
	advance(ms: number): void;
	/** How long after a revocation an authentication must come to count as after it. */
	readonly settlesAfterMs: number;
}

/** What every implementation of subject revocation must do, as a caller sees it. */
export function subjectRevocationContract(
	name: string,
	open: () => Promise<RevocationComposition>,
): void {
	describe(`subject revocation's contract: ${name}`, () => {
		it("revokes authentications of the subject up to the revocation, and only that subject's", async () => {
			const composition = await open();
			const before = composition.now() - 1000;
			expect(await composition.revocation.check("alice", before)).toBe("valid");
			await composition.revocation.revoke("alice");
			expect(await composition.revocation.check("alice", before)).toBe("revoked");
			expect(await composition.revocation.check("alice", composition.now())).toBe("revoked");
			// One second short of settling, an authentication still counts as before: comparison may be in seconds.
			expect(
				await composition.revocation.check(
					"alice",
					composition.now() + composition.settlesAfterMs - 1000,
				),
			).toBe("revoked");
			expect(
				await composition.revocation.check("alice", composition.now() + composition.settlesAfterMs),
			).toBe("valid");
			expect(await composition.revocation.check("bob", before)).toBe("valid");
		});

		it("moves the boundary forward with a later revocation", async () => {
			const composition = await open();
			await composition.revocation.revoke("alice");
			const between = composition.now() + composition.settlesAfterMs;
			expect(await composition.revocation.check("alice", between)).toBe("valid");
			composition.advance(composition.settlesAfterMs * 2);
			await composition.revocation.revoke("alice");
			expect(await composition.revocation.check("alice", between)).toBe("revoked");
		});

		it("answers erased where the record its write read carried the subject's mark, the key absent otherwise, and revokes all of a marked subject", async () => {
			const composition = await open();
			expect(await composition.revocations.record("alice")).toEqual({ complete: true });
			await composition.erasure.markErased("alice");
			await composition.erasure.markErased("carol");
			expect(await composition.revocations.record("alice")).toEqual({
				complete: true,
				erased: true,
			});
			// A subject marked before any revocation is answered erased at its first one.
			expect(await composition.revocations.record("carol")).toEqual({
				complete: true,
				erased: true,
			});
			expect(await composition.revocations.record("bob")).toEqual({ complete: true });
			const later = composition.now() + 365 * 86_400_000;
			expect(await composition.revocations.compare("alice", later, "delegations")).toBe("revoked");
			expect(await composition.revocation.check("carol", later)).toBe("revoked");
			expect(await composition.revocation.check("bob", later)).toBe("valid");
		});

		it("tells whether a subject is marked erased, read on every call", async () => {
			const composition = await open();
			expect(await composition.erasedSubjects.erased("alice")).toBe(false);
			await composition.revocations.record("alice");
			expect(await composition.erasedSubjects.erased("alice")).toBe(false);
			await composition.erasure.markErased("alice");
			await composition.erasure.markErased("carol");
			expect(await composition.erasedSubjects.erased("alice")).toBe(true);
			expect(await composition.erasedSubjects.erased("carol")).toBe(true);
			expect(await composition.erasedSubjects.erased("bob")).toBe(false);
		});

		it("moves sessions every time, and delegations unless kept", async () => {
			const composition = await open();
			const before = composition.now() - 1000;
			expect(await composition.revocations.record("alice", { keepDelegations: true })).toEqual({
				complete: true,
			});
			expect(await composition.revocations.compare("alice", before, "sessions")).toBe("revoked");
			expect(await composition.revocations.compare("alice", before, "delegations")).toBe("valid");
			await composition.revocations.record("alice");
			expect(await composition.revocations.compare("alice", before, "delegations")).toBe("revoked");
			expect(await composition.revocations.compare("bob", before, "delegations")).toBe("valid");
			const settled = composition.now() + composition.settlesAfterMs;
			expect(await composition.revocations.compare("alice", settled - 1000, "delegations")).toBe(
				"revoked",
			);
			expect(await composition.revocations.compare("alice", settled, "delegations")).toBe("valid");
		});

		it("leaves a kept delegations boundary where it was", async () => {
			const composition = await open();
			const before = composition.now() - 1000;
			await composition.revocations.record("alice");
			const between = composition.now() + composition.settlesAfterMs;
			composition.advance(composition.settlesAfterMs * 2);
			await composition.revocations.record("alice", { keepDelegations: true });
			expect(await composition.revocations.compare("alice", between, "sessions")).toBe("revoked");
			expect(await composition.revocations.compare("alice", between, "delegations")).toBe("valid");
			expect(await composition.revocations.compare("alice", before, "delegations")).toBe("revoked");
		});

		it("widens a boundary by the allowance a comparison gives, and by none when it gives none or less", async () => {
			const composition = await open();
			await composition.revocations.record("alice");
			const settled = composition.now() + composition.settlesAfterMs;
			const compare = (time: number, allowanceMs?: number) =>
				composition.revocations.compare("alice", time, "delegations", allowanceMs);
			expect(await compare(settled)).toBe("valid");
			expect(await compare(settled, 0)).toBe("valid");
			expect(await compare(settled, -5000)).toBe("valid");
			expect(await compare(settled + 1000, 2000)).toBe("revoked");
			expect(await compare(settled + 2000, 2000)).toBe("valid");
			expect(await composition.revocations.compare("bob", 0, "sessions", 2000)).toBe("valid");
		});

		it("revokes both boundaries, and checks against sessions", async () => {
			const composition = await open();
			const before = composition.now() - 1000;
			await composition.revocation.revoke("alice");
			expect(await composition.revocations.compare("alice", before, "delegations")).toBe("revoked");
			await composition.revocations.record("bob", { keepDelegations: true });
			expect(await composition.revocation.check("bob", before)).toBe("revoked");
		});
	});
}

/** `erased` from the stand-in's own marks, as the module answers it from the record its write read. */
const erasedOf = (held: Boundaries | undefined): { readonly erased?: true } =>
	held?.erasedAt === undefined ? {} : { erased: true };

/** Writes a revocation into the stand-in's map, answering whether it found a mark. */
const writtenInto =
	(boundaries: Map<string, Boundaries>, now: () => number): Write =>
	async (subject, keep) => {
		const held = boundaries.get(subject);
		boundaries.set(subject, recorded(held, now(), keep));
		return erasedOf(held);
	};

/**
 * Marks a subject erased in the stand-in's map by the module's rules: a first mark is kept and
 * answered; a subject with no boundary gets a `sessions` one at the mark's time.
 */
const markedInto =
	(boundaries: Map<string, Boundaries>, now: () => number): SubjectErasure["markErased"] =>
	async (subject) => {
		const held = boundaries.get(subject);
		if (held?.erasedAt !== undefined) return { kind: "marked", erasedAt: held.erasedAt };
		const erasedAt = now();
		boundaries.set(subject, { ...(held ?? recorded(undefined, erasedAt, true)), erasedAt });
		return { kind: "marked", erasedAt };
	};

/** Compares as the module does: an erased subject is revoked by every comparison. */
const comparedIn =
	(boundaries: () => Map<string, Boundaries>): Revocations["compare"] =>
	async (subject, time, kind, allowanceMs) => {
		const held = boundaries().get(subject);
		return held === undefined ? "valid" : comparedTo(held, time, kind, allowanceMs);
	};

/** Whether a subject is marked erased in the stand-in's map, as the module reads its mark. */
const erasedInto =
	(boundaries: () => Map<string, Boundaries>): ErasedSubjects["erased"] =>
	async (subject) =>
		boundaries().get(subject)?.erasedAt !== undefined;

/** One composition's boundaries, shared by its revocations and its marks. */
const standInBoundaries = contract<Map<string, Boundaries>>("subject-revocation.stand-in");

/**
 * A stand-in for tests of the modules that use subject revocation: boundaries kept in memory on
 * the composition's clock, recorded and compared by subject-revocation's own rules, and followed
 * by the contributed followers as there.
 */
export const subjectRevocationStandIn = defineModule(
	{ name: "subject-revocation", replicaSafe: false, takes: [revocationFollowers] },
	(m) => [
		m.provide(standInBoundaries).by(() => new Map<string, Boundaries>()),
		m.provide(revocations).by(async (c) => {
			const boundaries = await c.get(standInBoundaries);
			return {
				record: followedBy(
					writtenInto(boundaries, c.clock.now),
					await c.collect(revocationFollowers),
					c.log,
				),
				compare: comparedIn(() => boundaries),
			};
		}),
		m.provide(subjectRevocation).by(async (c) => subjectRevocationOf(await c.get(revocations))),
		m
			.provide(subjectErasure)
			.by(async (c) => ({ markErased: markedInto(await c.get(standInBoundaries), c.clock.now) })),
		m.provide(erasedSubjects).by(async (c) => {
			const boundaries = await c.get(standInBoundaries);
			return { erased: erasedInto(() => boundaries) };
		}),
	],
);

/**
 * The stand-in, with reads that can lag: from `lag()` until `catchUp()`, a compare or a check answers
 * by the boundaries as they stood at `lag()`, as a replica behind its primary would, while a record
 * moves them on. For a test of a grant whose read of the boundary answered stale.
 */
export function laggingRevocation() {
	let behind: Map<string, Boundaries> | undefined;
	const boundaries = new Map<string, Boundaries>();
	const module = defineModule(
		{ name: "subject-revocation", replicaSafe: false, takes: [revocationFollowers] },
		(m) => [
			m.provide(revocations).by(async (c) => ({
				record: followedBy(
					writtenInto(boundaries, c.clock.now),
					await c.collect(revocationFollowers),
					c.log,
				),
				compare: comparedIn(() => behind ?? boundaries),
			})),
			m.provide(subjectRevocation).by(async (c) => subjectRevocationOf(await c.get(revocations))),
			// A mark goes to the boundaries as they are; a lagging read sees it once caught up.
			m.provide(subjectErasure).by((c) => ({ markErased: markedInto(boundaries, c.clock.now) })),
			// Read as a compare is: by the boundaries as they stood at `lag()` until caught up.
			m.provide(erasedSubjects).by(() => ({ erased: erasedInto(() => behind ?? boundaries) })),
		],
	);
	return {
		module,
		lag: () => {
			behind = new Map(boundaries);
		},
		catchUp: () => {
			behind = undefined;
		},
	};
}

/** A place that keeps subject-revocation's boundaries, as one implementation of its store interface offers it. */
export interface BoundaryPlace {
	readonly boundaries: BoundaryStore;
	/** Moves the place's clock on. */
	advance(ms: number): void;
	/** Before the next update of `subject` writes, another writer changes its boundary as given. */
	raceNextUpdate(subject: string, change: (record: StoredBoundary) => StoredBoundary): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where it fences: before the next fence of `subject` writes, another writer changes its boundary. */
	readonly raceNextFence?: (
		subject: string,
		change: (record: StoredBoundary) => StoredBoundary,
	) => void;
	/** Where it tells whether erasure is enabled: enables it, as the erasure's tool does. */
	readonly enableErasure?: () => Promise<void>;
}

/**
 * What subject-revocation needs from any implementation of its store interface: boundaries kept
 * whole and once, changed only from what they hold, never ended, through faults.
 */
export function boundaryStoreContract(name: string, open: () => Promise<BoundaryPlace>): void {
	const fresh = () => `subject-${randomUUID()}`;
	const stored = (value: object) => value as unknown as StoredBoundary;
	const counted = (record: StoredBoundary) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredBoundary) => stored({ n: counted(record) + by });

	describe(`subject-revocation's store interface: ${name}`, () => {
		it("keeps a subject's first boundary whole and once, whatever it holds", async () => {
			const { boundaries } = await open();
			const subject = fresh();
			const odd = stored({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await boundaries.save(subject, () => odd, "endless")).toBe("created");
			expect(await boundaries.save(subject, () => stored({ n: 1 }), "endless")).toBe("exists");
			expect(await boundaries.read(subject)).toEqual(odd);
			expect(await boundaries.read(fresh())).toBeUndefined();
			expect(await boundaries.update(fresh(), plus(1))).toBeUndefined();
		});

		it("hands each save and update the write it is sent with, its deadline a number on the store's clock", async () => {
			const { boundaries } = await open();
			const subject = fresh();
			const handed: unknown[] = [];
			const saving = (write: BoundaryWrite) => {
				handed.push(write.deadline);
				return stored({ n: 1 });
			};
			await boundaries.save(subject, saving, "endless");
			await boundaries.update(subject, (record, write) => {
				handed.push(write.deadline);
				return plus(1)(record);
			});
			expect(handed).toHaveLength(2);
			for (const deadline of handed) expect(Number.isFinite(deadline)).toBe(true);
		});

		it("changes a boundary only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const subject = fresh();
			await place.boundaries.save(subject, () => stored({ n: 1 }), "endless");
			expect(await place.boundaries.update(subject, plus(1))).toEqual({
				before: stored({ n: 1 }),
				after: stored({ n: 2 }),
			});
			place.raceNextUpdate(subject, (record) => stored({ n: counted(record) * 10 }));
			expect((await place.boundaries.update(subject, plus(1)))?.after).toEqual(stored({ n: 21 }));
			expect(await place.boundaries.read(subject)).toEqual(stored({ n: 21 }));
		});

		it("never ends a boundary, saved or changed", async () => {
			const place = await open();
			const [saved, changed] = [fresh(), fresh()];
			await place.boundaries.save(saved, () => stored({ n: 1 }), "endless");
			await place.boundaries.save(changed, () => stored({ n: 1 }), "endless");
			await place.boundaries.update(changed, plus(1));
			place.advance(10 * 365 * 86_400_000);
			expect(await place.boundaries.read(saved)).toEqual(stored({ n: 1 }));
			expect(await place.boundaries.read(changed)).toEqual(stored({ n: 2 }));
		});

		// The fence and the mark are optional until 0.22: their cases run where the implementation has them.
		it("fences: keeps the receipt allowed makes from the boundary as read, none where it makes none", async (context) => {
			const place = await open();
			const fence = place.boundaries.fence?.bind(place.boundaries);
			if (!fence) return context.skip();
			const made = (id: string) => ({ id }) as unknown as StoredReceipt;
			const write = (id: string) => ({ value: made(id), lifetimeMs: 60_000 });
			const subject = fresh();
			const seen: unknown[] = [];
			const allowing = (record: StoredBoundary | undefined) => {
				seen.push(record);
				return write("r1");
			};
			expect(await fence(subject, fresh(), allowing)).toEqual({
				before: undefined,
				after: made("r1"),
			});
			expect(seen).toEqual([undefined]);
			await place.boundaries.save(subject, () => stored({ n: 1 }), "endless");
			expect((await fence(subject, fresh(), () => undefined)).after).toBeUndefined();
			// A receipt already under the id is answered as `before`, and kept where `allowed` makes none.
			const taken = fresh();
			await fence(fresh(), taken, () => write("r2"));
			expect(await fence(subject, taken, () => undefined)).toEqual({
				before: made("r2"),
				after: made("r2"),
			});
			if (place.raceNextFence) {
				seen.length = 0;
				place.raceNextFence(subject, (record) => stored({ n: counted(record) + 1 }));
				await fence(subject, fresh(), allowing);
				expect(seen.at(-1)).toEqual(stored({ n: 2 }));
			}
		});

		it("tells whether erasure is enabled, and enabled once it is", async (context) => {
			const place = await open();
			const enabled = place.boundaries.erasureEnabled?.bind(place.boundaries);
			if (!enabled) return context.skip();
			expect(typeof (await enabled())).toBe("boolean");
			if (!place.enableErasure) return;
			await place.enableErasure();
			expect(await enabled()).toBe(true);
		});

		it("keeps boundaries through lost answers, a failover, a restart and memory pressure", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [saved, changed] = [fresh(), fresh()];
			lose();
			expect(await place.boundaries.save(saved, () => stored({ n: 1 }), "endless")).toBe("created");
			await place.boundaries.save(changed, () => stored({ n: 1 }), "endless");
			lose();
			expect((await place.boundaries.update(changed, plus(1)))?.after).toEqual(stored({ n: 2 }));
			await failover();
			await restart();
			await pressMemory();
			expect(await place.boundaries.read(saved)).toEqual(stored({ n: 1 }));
			expect(await place.boundaries.read(changed)).toEqual(stored({ n: 2 }));
		});
	});
}
