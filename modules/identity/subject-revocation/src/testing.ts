import { randomUUID } from "node:crypto";
import { defineModule } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	type Boundaries,
	compared,
	recorded,
	subjectRevocationOf,
} from "./boundaries/boundaries.ts";
import {
	type Revocations,
	revocationFollowers,
	revocations,
	type SubjectRevocation,
	subjectRevocation,
} from "./contract.ts";
import { followedBy, type Write } from "./followers.ts";
import type { BoundaryStore, StoredBoundary } from "./store.ts";

/** A composition that offers subject revocation, as one implementation of the contract does. */
export interface RevocationComposition {
	readonly revocation: SubjectRevocation;
	readonly revocations: Revocations;
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

/**
 * A stand-in for tests of the modules that use subject revocation: boundaries kept in memory on
 * the composition's clock, recorded and compared by subject-revocation's own rules, and followed
 * by the contributed followers as there.
 */
export const subjectRevocationStandIn = defineModule(
	{ name: "subject-revocation", takes: [revocationFollowers] },
	(m) => [
		m.provide(revocations).by(async (c) => {
			const boundaries = new Map<string, Boundaries>();
			const write: Write = async (subject, keep) => {
				boundaries.set(subject, recorded(boundaries.get(subject), c.clock.now(), keep));
			};
			return {
				record: followedBy(write, await c.collect(revocationFollowers), c.log),
				compare: async (subject, time, kind, allowanceMs) =>
					compared(time, boundaries.get(subject)?.[kind], allowanceMs),
			};
		}),
		m.provide(subjectRevocation).by(async (c) => subjectRevocationOf(await c.get(revocations))),
	],
);

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
			expect(await boundaries.save(subject, odd, "endless")).toBe("created");
			expect(await boundaries.save(subject, stored({ n: 1 }), "endless")).toBe("exists");
			expect(await boundaries.read(subject)).toEqual(odd);
			expect(await boundaries.read(fresh())).toBeUndefined();
			expect(await boundaries.update(fresh(), plus(1))).toBeUndefined();
		});

		it("changes a boundary only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const subject = fresh();
			await place.boundaries.save(subject, stored({ n: 1 }), "endless");
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
			await place.boundaries.save(saved, stored({ n: 1 }), "endless");
			await place.boundaries.save(changed, stored({ n: 1 }), "endless");
			await place.boundaries.update(changed, plus(1));
			place.advance(10 * 365 * 86_400_000);
			expect(await place.boundaries.read(saved)).toEqual(stored({ n: 1 }));
			expect(await place.boundaries.read(changed)).toEqual(stored({ n: 2 }));
		});

		it("keeps boundaries through lost answers, a failover, a restart and memory pressure", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover, restart, pressMemory } = place;
			if (!lose || !failover || !restart || !pressMemory) return context.skip();
			const [saved, changed] = [fresh(), fresh()];
			lose();
			expect(await place.boundaries.save(saved, stored({ n: 1 }), "endless")).toBe("created");
			await place.boundaries.save(changed, stored({ n: 1 }), "endless");
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
