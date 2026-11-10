import {
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import {
	erasureFence,
	erasureGuards,
	revocations,
	subjectErasure,
	subjectRevocation,
} from "../src/contract.ts";
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

it("never writes a boundary over a mark it cannot read: the revocation is unavailable, the mark stays", async () => {
	const { revocations: boundaries, revocation, kept } = await boot();
	const odd = { sessions: 1, erasedAt: "x" } as unknown as StoredBoundary;
	await kept.records.create("alice", odd, "endless");
	const failed = await boundaries.record("alice").catch((e: unknown) => e);
	expect(isUnavailable(failed)).toBe(true);
	expect(await kept.records.read("alice")).toEqual(odd);
	expect(isUnavailable(await revocation.check("alice", now).catch((e: unknown) => e))).toBe(true);
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

/** subject-revocation guarded or not, over a store as given; its readiness, its warnings, or why its boot was refused. */
async function gated(
	guarded: boolean,
	set: (stores: ReturnType<typeof memoryBoundaries>) => void,
	has: Parameters<typeof memoryBoundaries>[1] = {},
) {
	const stores = memoryBoundaries(() => now, has);
	set(stores);
	const recorded = recordingLog();
	let context: BuildContext<unknown> | undefined;
	const booted = assemble({
		modules: [
			revocationModule,
			defineModule({ name: "boundaries", replicaSafe: false, takes: [] }, (m) => [
				m.provide(boundaryStore).by(() => stores.boundaries),
			]),
			defineModule({ name: "guard", replicaSafe: false, takes: [] }, (m) =>
				guarded ? [m.contribute(erasureGuards).by(() => ({ name: "guard" }))] : [],
			),
			defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
				m.provide(contract<object>("asker")).by((c) => {
					context = c;
					return {};
				}),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => now }, log: recorded.log }),
	});
	const app = await booted.catch((error: unknown) => {
		if (error instanceof BootRefused) return error;
		throw error;
	});
	return {
		...stores,
		refused: app instanceof BootRefused ? JSON.stringify(app.refusals) : undefined,
		app: app instanceof BootRefused ? undefined : app,
		ready: () => context?.readinessReport(1000).then((r) => r.answer),
		warned: () =>
			recorded
				.lines()
				.filter((l) => l.level === "warn")
				.map((l) => l.event),
		unknownWhy: () =>
			recorded
				.lines()
				.filter((l) => l.event === "subject-revocation.erasure_unknown")
				.map((l) => String(l.fields.reason)),
	};
}

it("refuses to start where erasure is enabled and the composition does not guard it", async () => {
	const on = (s: ReturnType<typeof memoryBoundaries>) => {
		s.erasure.on = true;
	};
	expect((await gated(false, on)).refused).toMatch(/subject-revocation/);
	expect((await gated(true, on, { fence: false })).refused).toMatch(/subject-revocation/);
	expect((await gated(true, on)).refused).toBeUndefined();
});

it("starts a guarded composition with its store down, reading no mark, and ready", async () => {
	const booted = await gated(true, (s) => {
		s.down.unavailable("read", "save", "update");
		s.erasure.unreadable = true;
	});
	expect(booted.refused).toBeUndefined();
	expect(await booted.ready()).toBe("ready");
});

it("starts an unguarded composition unready while the mark cannot be read, ready once it reads off", async () => {
	const booted = await gated(false, (s) => {
		s.erasure.unreadable = true;
	});
	expect(booted.refused).toBeUndefined();
	expect(await booted.ready()).toBe("unready");
	booted.erasure.unreadable = false;
	expect(await booted.ready()).toBe("ready");
});

it("fences only where erasure is on or unread: a receipt where the subject is not erased, nothing where it is", async () => {
	const off = await gated(true, () => {});
	expect(await off.app?.get(erasureFence).fence("alice", "r0")).toBe("passed");
	expect(off.receipts.size).toBe(0);
	const unread = await gated(true, (s) => {
		s.erasure.unreadable = true;
	});
	expect(await unread.app?.get(erasureFence).fence("alice", "r1")).toBe("passed");
	expect([...unread.receipts.keys()]).toEqual(["r1"]);
	const on = await gated(true, (s) => {
		s.erasure.on = true;
	});
	const fence = on.app?.get(erasureFence);
	expect(await fence?.fence("alice", "r2")).toBe("passed");
	await on.app?.get(subjectErasure).markErased("alice");
	expect(await fence?.fence("alice", "r3")).toBe("erased");
	expect(await fence?.fence("bob", "r4")).toBe("passed");
	expect([...on.receipts.keys()]).toEqual(["r2", "r4"]);
});

it("never passes a fence whose receipt id already holds a receipt, whatever the boundary holds", async () => {
	const on = await gated(true, (s) => {
		s.erasure.on = true;
	});
	const fence = on.app?.get(erasureFence);
	expect(await fence?.fence("bob", "r")).toBe("passed");
	await expect(fence?.fence("carol", "r")).rejects.toThrow("receipt id");
	await on.app?.get(subjectErasure).markErased("alice");
	await expect(fence?.fence("alice", "r")).rejects.toThrow("receipt id");
	expect(await fence?.fence("alice", "r5")).toBe("erased");
});

it("takes erasure as off, warning at every start, where the store can neither tell whether it is enabled nor fence", async () => {
	const booted = await gated(false, () => {}, { erasureEnabled: false, fence: false });
	expect(booted.unknownWhy()).toEqual([expect.stringContaining("nor fences")]);
	expect(await booted.app?.get(erasureFence).fence("alice", "r0")).toBe("passed");
	expect(await booted.ready()).toBe("ready");
});

it("fences every bundle where the store fences but cannot tell whether erasure is enabled, its start and readiness as off", async () => {
	for (const guarded of [true, false]) {
		const booted = await gated(guarded, () => {}, { erasureEnabled: false });
		expect(booted.unknownWhy()).toEqual([
			guarded
				? expect.stringContaining("every bundle is fenced")
				: expect.stringContaining("no module guards it"),
		]);
		expect(await booted.ready()).toBe("ready");
		const fence = booted.app?.get(erasureFence);
		expect(await fence?.fence("alice", "r0")).toBe("passed");
		await booted.app?.get(subjectErasure).markErased("alice");
		expect(await fence?.fence("alice", "r1")).toBe("erased");
		expect([...booted.receipts.keys()]).toEqual(["r0"]);
	}
});
