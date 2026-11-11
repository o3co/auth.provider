import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import {
	erasedSubjects,
	revocationFollowers,
	revocations,
	subjectErasure,
} from "../src/contract.ts";
import revocationModule from "../src/module.ts";
import { type BoundaryStore, boundaryStore } from "../src/store.ts";
import { memoryBoundaries } from "./stores.ts";

const now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });

/** A follower noting what each call was told. */
function telling() {
	const told: unknown[] = [];
	const module = defineModule({ name: "told", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(revocationFollowers).by(() => ({
			name: "told",
			follow: async (subject, revocation) => {
				told.push({ subject, ...revocation });
			},
		})),
	]);
	return { told, module };
}

/** subject-revocation over the records stand-in, its store as given, and a follower noting each call. */
async function boot(wrap: (store: BoundaryStore) => BoundaryStore = (store) => store) {
	const stores = memoryBoundaries(() => now);
	const follower = telling();
	const app = await assemble({
		modules: [
			revocationModule,
			defineModule({ name: "boundaries", replicaSafe: false, takes: [] }, (m) => [
				m.provide(boundaryStore).by(() => wrap(stores.boundaries)),
			]),
			follower.module,
		],
		config: kernelConfig(),
		runtime,
	});
	return {
		...stores,
		told: follower.told,
		revocations: app.get(revocations),
		erasure: app.get(subjectErasure),
		erasedSubjects: app.get(erasedSubjects),
	};
}

it("answers erased where the record its write read carried a mark, telling each follower so, the key absent otherwise", async () => {
	const { revocations: r, erasure, told } = await boot();
	expect(await r.record("alice")).toEqual({ complete: true });
	expect(await r.record("alice", { keepDelegations: true })).toEqual({ complete: true });
	await erasure.markErased("alice");
	expect(await r.record("alice", { keepDelegations: true })).toEqual({
		complete: true,
		erased: true,
	});
	// A subject first recorded after another's erasure is not erased.
	expect(await r.record("bob")).toEqual({ complete: true });
	expect(told).toEqual([
		{ subject: "alice", keepDelegations: false },
		{ subject: "alice", keepDelegations: true },
		{ subject: "alice", keepDelegations: true, erased: true },
		{ subject: "bob", keepDelegations: false },
	]);
});

it("answers from the attempt whose write committed: a mark written between attempts is answered", async () => {
	let raced = false;
	const {
		revocations: r,
		kept,
		told,
	} = await boot((store) => ({
		...store,
		update: async (subject, change) => {
			if (!raced) {
				raced = true;
				// An attempt reads the record as it stands, then loses its write to the mark landing.
				const before = await kept.records.read(subject);
				if (before !== undefined) change(before, { deadline: now });
				await kept.records.change(subject, (record) => ({
					value: { ...(record as object), erasedAt: now } as never,
				}));
			}
			return store.update(subject, change);
		},
	}));
	await kept.records.create("alice", { sessions: now - 60_000 } as never, "endless");
	expect(await r.record("alice")).toEqual({ complete: true, erased: true });
	expect(told).toEqual([{ subject: "alice", keepDelegations: false, erased: true }]);
});

it("is unavailable, telling no follower, where the record carries a mark that is no time", async () => {
	const { revocations: r, kept, told } = await boot();
	await kept.records.create("alice", { sessions: now, erasedAt: "soon" } as never, "endless");
	await expect(r.record("alice")).rejects.toSatisfy(isUnavailable);
	expect(told).toEqual([]);
});

it("reads erased from the mark alone: a mark of a time beside a part that cannot be read is erased; none, or no record, is not", async () => {
	const { erasedSubjects: port, kept } = await boot();
	await kept.records.create("alice", { sessions: "soon", erasedAt: now } as never, "endless");
	await kept.records.create("bob", { sessions: now } as never, "endless");
	expect(await port.erased("alice")).toBe(true);
	expect(await port.erased("bob")).toBe(false);
	expect(await port.erased("carol")).toBe(false);
});

it("is unavailable where the record carries a mark that is no time, never not erased", async () => {
	const { erasedSubjects: port, kept, down } = await boot();
	await kept.records.create("alice", { sessions: now, erasedAt: "soon" } as never, "endless");
	await expect(port.erased("alice")).rejects.toSatisfy(isUnavailable);
	down.failNext("read");
	await expect(port.erased("bob")).rejects.toSatisfy(isUnavailable);
});
