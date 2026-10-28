import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { revocations, subjectRevocation } from "../src/contract.ts";
import revocationModule from "../src/module.ts";
import { type BoundaryStore, boundaryStore, type StoredBoundary } from "../src/store.ts";
import { subjectRevocationContract, subjectRevocationStandIn } from "../src/testing.ts";
import { memoryBoundaries } from "./stores.ts";

const now = 1_800_000_000_000;
const stored = (at: number) => at as unknown as StoredBoundary;

/** A runtime whose clock the test moves, and the adapter the contract test reads it by. */
function movable() {
	const clock = { at: now };
	const runtime = quietRuntime({
		clock: { now: () => clock.at },
		random: { bytes: (n) => new Uint8Array(n) },
	});
	const adapter = {
		now: () => clock.at,
		advance: (ms: number) => {
			clock.at += ms;
		},
		settlesAfterMs: 1000,
	};
	return { clock, runtime, adapter };
}

/** subject-revocation over the records stand-in, on a clock the test moves; `front` may stand in front of the store. */
async function boot(front: (boundaries: BoundaryStore) => BoundaryStore = (b) => b) {
	const stores = memoryBoundaries();
	const { clock, runtime, adapter } = movable();
	const app = await assemble({
		modules: [
			revocationModule,
			defineModule({ name: "boundaries", replicaSafe: true, takes: [] }, (m) => [
				m.provide(boundaryStore).by(() => front(stores.boundaries)),
			]),
		],
		config: kernelConfig(),
		runtime,
	});
	const revocation = app.get(subjectRevocation);
	return { ...stores, clock, adapter, revocation, revocations: app.get(revocations) };
}

it("refuses authentications up to the boundary's second, and only for that subject", async () => {
	const { revocation } = await boot();
	const before = now - 1000;
	expect(await revocation.check("alice", before)).toBe("valid");
	await revocation.revoke("alice");
	expect(await revocation.check("alice", before)).toBe("revoked");
	expect(await revocation.check("alice", now + 999)).toBe("revoked");
	expect(await revocation.check("alice", now + 1000)).toBe("valid");
	expect(await revocation.check("bob", before)).toBe("valid");
});

it("revokes what started within the allowance after the boundary's second, and refuses an allowance that is no number", async () => {
	const { revocation, revocations } = await boot();
	await revocation.revoke("alice");
	expect(await revocations.compare("alice", now + 2999, "sessions", 2000)).toBe("revoked");
	expect(await revocations.compare("alice", now + 3000, "sessions", 2000)).toBe("valid");
	expect(await revocations.compare("alice", now + 1000, "sessions", 1)).toBe("valid");
	expect(await revocations.compare("alice", now, "sessions", -5000)).toBe("revoked");
	expect(await revocations.compare("alice", now + 1000, "sessions", Number.NaN)).toBe("revoked");
	expect(
		await revocations.compare("alice", now + 60_000, "sessions", Number.POSITIVE_INFINITY),
	).toBe("revoked");
});

it("takes the boundary from the kernel's clock, whatever the store's clock says", async () => {
	const { advanceStore, revocation } = await boot();
	advanceStore(60_000);
	await revocation.revoke("alice");
	expect(await revocation.check("alice", now)).toBe("revoked");
	expect(await revocation.check("alice", now + 1000)).toBe("valid");
});

it("never moves the boundary back, from a later revocation or another writer's", async () => {
	const { clock, kept, revocation, revocations } = await boot();
	await revocation.revoke("alice");
	clock.at = now - 60_000;
	await revocation.revoke("alice");
	expect(await revocation.check("alice", now - 1000)).toBe("revoked");
	expect(await revocations.compare("alice", now - 1000, "delegations")).toBe("revoked");
	kept.raceNextChange(() => stored(now + 60_000));
	await revocation.revoke("alice");
	expect(await revocation.check("alice", now + 59_000)).toBe("revoked");
});

it("saves a first boundary, and moves one the subject holds, with one write each", async () => {
	const calls: string[] = [];
	const { revocation } = await boot((b) => ({
		...b,
		save: (subject, record, lifetimeMs) => {
			calls.push("save");
			return b.save(subject, record, lifetimeMs);
		},
		update: (subject, change) => {
			calls.push("update");
			return b.update(subject, change);
		},
	}));
	await revocation.revoke("alice");
	expect(calls).toEqual(["update", "save"]);
	calls.length = 0;
	await revocation.revoke("alice");
	expect(calls).toEqual(["update"]);
});

it("is unavailable when a boundary holds no time, and a revocation moves both kinds over it", async () => {
	const { boundaries, revocation, revocations } = await boot();
	await boundaries.save("alice", { at: now } as unknown as StoredBoundary, "endless");
	await boundaries.save(
		"bob",
		{ sessions: now, delegations: "soon" } as unknown as StoredBoundary,
		"endless",
	);
	await expect(revocation.check("alice", now - 1000)).rejects.toSatisfy(isUnavailable);
	await expect(revocations.compare("alice", now - 1000, "delegations")).rejects.toSatisfy(
		isUnavailable,
	);
	await expect(revocations.compare("bob", now - 1000, "sessions")).rejects.toSatisfy(isUnavailable);
	await boundaries.save("carol", null as unknown as StoredBoundary, "endless");
	await expect(revocations.compare("carol", now - 1000, "sessions")).rejects.toSatisfy(
		isUnavailable,
	);
	await revocations.record("alice", { keepDelegations: true });
	expect(await revocations.compare("alice", now - 1000, "sessions")).toBe("revoked");
	expect(await revocations.compare("alice", now - 1000, "delegations")).toBe("revoked");
	expect(await revocations.compare("alice", now + 1000, "delegations")).toBe("valid");
});

it("reads a boundary of one time as both kinds", async () => {
	const { boundaries, revocations } = await boot();
	await boundaries.save("alice", stored(now), "endless");
	expect(await revocations.compare("alice", now - 1000, "sessions")).toBe("revoked");
	expect(await revocations.compare("alice", now - 1000, "delegations")).toBe("revoked");
	expect(await revocations.compare("alice", now + 1000, "delegations")).toBe("valid");
	await revocations.record("alice", { keepDelegations: true });
	expect(await revocations.compare("alice", now - 1000, "delegations")).toBe("revoked");
});

it("moves a first boundary another writer saved first", async () => {
	const { revocation } = await boot((b) => ({
		...b,
		save: async (subject, record, lifetimeMs) => {
			await b.save(subject, stored(now - 60_000), lifetimeMs);
			return b.save(subject, record, lifetimeMs);
		},
	}));
	await revocation.revoke("alice");
	expect(await revocation.check("alice", now - 1000)).toBe("revoked");
});

it("writes even when the boundary is already far enough, so an unconfirmed boundary is not taken as done", async () => {
	const { clock, down, revocation } = await boot();
	await revocation.revoke("alice");
	clock.at = now - 60_000;
	down.failNext("update");
	await expect(revocation.revoke("alice")).rejects.toSatisfy(isUnavailable);
});

it("is unavailable rather than valid or recorded when the store cannot tell", async () => {
	const { down, revocation } = await boot();
	down.failNext("read");
	await expect(revocation.check("alice", now)).rejects.toSatisfy(isUnavailable);
	down.failNext("save");
	await expect(revocation.revoke("alice")).rejects.toSatisfy(isUnavailable);
});

it("is unavailable when another request's first boundary is gone before it moves", async () => {
	const { revocation } = await boot((b) => ({
		...b,
		update: async () => undefined,
		save: async () => "exists",
	}));
	await expect(revocation.revoke("alice")).rejects.toSatisfy(isUnavailable);
});

subjectRevocationContract("subject-revocation over the records stand-in", async () => {
	const { adapter, revocation, revocations } = await boot();
	return { revocation, revocations, ...adapter };
});

subjectRevocationContract("the stand-in", async () => {
	const { runtime, adapter } = movable();
	const app = await assemble({
		modules: [subjectRevocationStandIn],
		config: kernelConfig(),
		runtime,
	});
	return { revocation: app.get(subjectRevocation), revocations: app.get(revocations), ...adapter };
});

it("takes every handle its takes name, the module and its stand-in alike", async () => {
	const stores = memoryBoundaries();
	const boundaries = defineModule({ name: "boundaries", replicaSafe: true, takes: [] }, (m) => [
		m.provide(boundaryStore).by(() => stores.boundaries),
	]);
	const config = kernelConfig();
	expect(
		(await takesUnused({ modules: [revocationModule, boundaries], config }))["subject-revocation"],
	).toBeUndefined();
	expect(
		(await takesUnused({ modules: [subjectRevocationStandIn], config }))["subject-revocation"],
	).toBeUndefined();
});
