import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { revocations, subjectErasure, subjectRevocation } from "../src/contract.ts";
import revocationModule from "../src/module.ts";
import { boundaryStore, type StoredBoundary } from "../src/store.ts";
import { memoryBoundaries } from "./stores.ts";

const now = 1_800_000_000_000;
/** How far past its store-clock time a boundary's write may land: records' patience, its deadline. */
const patience = 10_000;

/** subject-revocation over the records stand-in, its erasure taken as account erasure will take it. */
async function boot() {
	const stores = memoryBoundaries(() => now);
	const app = await assemble({
		modules: [
			revocationModule,
			defineModule({ name: "boundaries", replicaSafe: false, takes: [] }, (m) => [
				m.provide(boundaryStore).by(() => stores.boundaries),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => now } }),
	});
	return {
		...stores,
		revocation: app.get(subjectRevocation),
		revocations: app.get(revocations),
		erasure: app.get(subjectErasure),
	};
}

it("refuses everything of an erased subject, whatever its time, kind or allowance, and only that subject", async () => {
	const { revocation, revocations: boundaries, erasure } = await boot();
	expect(await erasure.markErased("alice")).toEqual({ kind: "marked", erasedAt: now + patience });
	const later = now + 365 * 86_400_000;
	expect(await revocation.check("alice", later)).toBe("revoked");
	expect(await boundaries.compare("alice", later, "delegations")).toBe("revoked");
	expect(await boundaries.compare("alice", now - 1000, "sessions", -5)).toBe("revoked");
	expect(await revocation.check("bob", later)).toBe("valid");
});

it("keeps the boundaries a mark finds, and the first mark through later marks and revocations", async () => {
	const { revocations: boundaries, erasure, kept, advanceStore } = await boot();
	await boundaries.record("alice", { keepDelegations: true });
	const before = await kept.records.read("alice");
	expect(before).toEqual({ sessions: now + patience });
	const { erasedAt } = await erasure.markErased("alice");
	expect(await kept.records.read("alice")).toEqual({ sessions: now + patience, erasedAt });
	advanceStore(60_000);
	expect(await erasure.markErased("alice")).toEqual({ kind: "marked", erasedAt });
	await boundaries.record("alice");
	expect(await kept.records.read("alice")).toMatchObject({ erasedAt });
});

it("marks a subject a record of no time holds as one revoked now, and reads a mark of no time as unavailable", async () => {
	const { revocation, erasure, kept } = await boot();
	await kept.records.create("old", "no time" as unknown as StoredBoundary, "endless");
	expect((await erasure.markErased("old")).erasedAt).toBe(now + patience);
	await kept.records.create(
		"odd",
		{ sessions: 1, erasedAt: "x" } as unknown as StoredBoundary,
		"endless",
	);
	const failed = await revocation.check("odd", now).catch((e: unknown) => e);
	expect(isUnavailable(failed)).toBe(true);
});

it("lets no module take the erasure until account erasure is named", async () => {
	const stores = memoryBoundaries(() => now);
	const assembled = assemble({
		modules: [
			revocationModule,
			defineModule({ name: "boundaries", replicaSafe: false, takes: [] }, (m) => [
				m.provide(boundaryStore).by(() => stores.boundaries),
			]),
			defineModule({ name: "eraser", replicaSafe: false, takes: [subjectErasure] }, () => []),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const refused = await assembled.then(
		() => [],
		(error: unknown) => (error instanceof BootRefused ? error.refusals : [error]),
	);
	expect(JSON.stringify(refused)).toMatch(/subject-revocation\.erasure/);
});
