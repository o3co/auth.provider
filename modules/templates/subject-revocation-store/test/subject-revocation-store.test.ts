import { erasureMarks } from "@mod/erasure-extensions";
import { assemble, BootRefused, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type Store, store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import {
	boundaryStore,
	erasureFence,
	erasureGuards,
	revocations,
	subjectErasure,
	subjectRevocation,
} from "@mod/subject-revocation";
import revocationModule from "@mod/subject-revocation/module";
import { boundaryStoreContract } from "@mod/subject-revocation/testing";
import { describe, expect, it } from "vitest";
import wiring from "../src/module.ts";

const space = "subject-revocation-store.boundaries";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

boundaryStoreContract(
	"subject-revocation-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const boundaries = app.get(boundaryStore);
		return {
			boundaries,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (subject, change) =>
				simulated.beforeNext("replaceIf", "subject-revocation-store.boundaries", async () => {
					await boundaries.update(subject, change);
				}),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			restart: () => simulated.restart(),
			pressMemory: () => simulated.pressMemory(),
			raceNextFence: (subject, change) =>
				simulated.beforeNext("batchAcross", "subject-revocation-store.receipts", async () => {
					await boundaries.update(subject, change);
				}),
			enableErasure: async () => simulated.mark(erasureMarks.enabled, true),
		};
	},
);

describe("subject-revocation over the wiring", () => {
	const now = 1_800_000_000_000;
	async function composed() {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring, revocationModule],
			config: kernelConfig(),
			runtime,
		});
		return { simulated, revocations: app.get(revocations) };
	}

	it("records a boundary, first and moved, as the deadline its write is sent with on the store's clock", async () => {
		const { simulated, revocations: r } = await composed();
		// The store's clock runs 2 s ahead: each write's deadline is 12 s past the host's time.
		simulated.shiftClock(2000);
		await r.record("alice");
		expect(await r.compare("alice", now + 12_999, "sessions")).toBe("revoked");
		expect(await r.compare("alice", now + 13_000, "sessions")).toBe("valid");
		simulated.shiftClock(5000);
		await r.record("alice");
		expect(await r.compare("alice", now + 17_999, "sessions")).toBe("revoked");
		expect(await r.compare("alice", now + 18_000, "sessions")).toBe("valid");
	});

	it("is unavailable for a write that lands past its deadline, recording nothing, and records when sent again", async () => {
		const { simulated, revocations: r } = await composed();
		simulated.beforeNext("putIfAbsent", space, async () => simulated.shiftClock(11_000));
		await expect(r.record("bob")).rejects.toSatisfy(isUnavailable);
		expect(await r.compare("bob", now, "sessions")).toBe("valid");
		await r.record("bob");
		expect(await r.compare("bob", now + 11_000, "sessions")).toBe("revoked");
	});
});

describe("subject-revocation's erasure over the wiring", () => {
	const guard = defineModule({ name: "guard", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(erasureGuards).by(() => ({ name: "guard" })),
	]);
	async function composed(
		guarded: boolean,
		before: (s: ReturnType<typeof simulatedStore>) => void,
	) {
		const simulated = simulatedStore();
		before(simulated);
		const app = await assemble({
			modules: [simulated.module, wiring, revocationModule, ...(guarded ? [guard] : [])],
			config: kernelConfig(),
			runtime,
		});
		return { simulated, app };
	}

	it("fences against the mark of erasure: a receipt of a minute where none stands, none where it does", async () => {
		const { simulated, app } = await composed(true, () => {});
		simulated.mark(erasureMarks.enabled, true);
		await app.get(subjectErasure).markErased("alice");
		const fence = app.get(erasureFence);
		expect(await fence.fence("alice", "r1")).toBe("erased");
		expect(await fence.fence("bob", "r2")).toBe("passed");
		const kept = await app.get(store).get({
			space: { name: "subject-revocation-store.receipts", guarantees: [] },
			partition: "r2",
			name: "record",
		});
		expect(kept.entry?.value).toEqual({ id: "r2" });
		simulated.shiftClock(61_000);
		expect(
			(
				await app.get(store).get({
					space: { name: "subject-revocation-store.receipts", guarantees: [] },
					partition: "r2",
					name: "record",
				})
			).entry,
		).toBeNull();
	});

	it("starts a guarded and an unguarded composition with the store unreachable, refusing neither", async () => {
		const guarded = await composed(true, (s) => s.unreachable(true));
		expect(guarded.app).toBeDefined();
		const unguarded = await composed(false, (s) => s.unreachable(true));
		expect(unguarded.app).toBeDefined();
	});
});

it("boots over a store that offers no control record, erasure unknown: it warns at every start and fences every bundle", async () => {
	const simulated = simulatedStore();
	// A store adapter of 0.19: the simulated store's own provisions but its control record.
	const uncontrolled = {
		...simulated.module,
		provides: (simulated.module.provides ?? []).filter((p) => p.contract !== storeControl),
	};
	const recorded = recordingLog();
	const app = await assemble({
		modules: [uncontrolled, wiring, revocationModule],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => 1_800_000_000_000 }, log: recorded.log }),
	});
	expect(app.get(boundaryStore).erasureEnabled).toBeUndefined();
	expect(recorded.lines().map((line) => line.event)).toContain(
		"subject-revocation.erasure_unknown",
	);
	expect(await app.get(erasureFence).fence("alice", "r1")).toBe("passed");
	await app.get(subjectErasure).markErased("alice");
	expect(await app.get(erasureFence).fence("alice", "r2")).toBe("erased");
});

/** The simulated store, its batch across partitions taken away: a store that writes none as one. */
function storeWithin() {
	const simulated = simulatedStore();
	const module = {
		...simulated.module,
		provides: (simulated.module.provides ?? []).map((p) =>
			p.contract === store
				? {
						...p,
						create: async (c: never) => {
							const { batchAcross: _, ...within } = (await p.create(c)) as Store;
							return within;
						},
					}
				: p,
		),
	};
	return { simulated, module };
}

it("boots over a store that writes no two partitions as one, offering no fence, refused only where erasure is enabled", async () => {
	const off = storeWithin();
	const app = await assemble({
		modules: [off.module, wiring, revocationModule],
		config: kernelConfig(),
		runtime,
	});
	expect(app.get(boundaryStore).fence).toBeUndefined();
	expect(await app.get(subjectRevocation).check("alice", 1)).toBe("valid");
	expect(await app.get(erasureFence).fence("alice", "r1")).toBe("passed");
	const on = storeWithin();
	on.simulated.mark(erasureMarks.enabled, true);
	const refused = await assemble({
		modules: [on.module, wiring, revocationModule],
		config: kernelConfig(),
		runtime,
	}).catch((error: unknown) => (error instanceof BootRefused ? error.refusals : [error]));
	expect(JSON.stringify(refused)).toContain("the boundary store does not fence");
});
