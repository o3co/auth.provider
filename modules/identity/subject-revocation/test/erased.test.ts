import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import {
	erasedSubjects,
	erasureGuards,
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
async function boot(
	wrap: (store: BoundaryStore) => BoundaryStore = (store) => store,
	reads: { readonly on?: boolean; readonly unreadable?: boolean } = {},
) {
	const stores = memoryBoundaries(() => now);
	// As the store reads erasure at this process's start, which holds it.
	Object.assign(stores.erasure, reads);
	const follower = telling();
	const app = await assemble({
		modules: [
			revocationModule,
			defineModule({ name: "boundaries", replicaSafe: false, takes: [] }, (m) => [
				m.provide(boundaryStore).by(() => wrap(stores.boundaries)),
				// Guarded, as a composition where erasure may be enabled is.
				m.contribute(erasureGuards).by(() => ({ name: "test" })),
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
	const { erasedSubjects: port, kept } = await boot(undefined, { on: true });
	await kept.records.create("alice", { sessions: "soon", erasedAt: now } as never, "endless");
	await kept.records.create("bob", { sessions: now } as never, "endless");
	expect(await port.erased("alice")).toBe(true);
	expect(await port.erased("bob")).toBe(false);
	expect(await port.erased("carol")).toBe(false);
});

it("is unavailable where the record carries a mark that is no time, never not erased", async () => {
	const { erasedSubjects: port, kept, down } = await boot(undefined, { on: true });
	await kept.records.create("alice", { sessions: now, erasedAt: "soon" } as never, "endless");
	await expect(port.erased("alice")).rejects.toSatisfy(isUnavailable);
	down.failNext("read");
	await expect(port.erased("bob")).rejects.toSatisfy(isUnavailable);
});

it("reads nothing where erasure was read off at start, answering not erased; reads the store once read on, or while unread", async () => {
	let reads = 0;
	const counted = (store: BoundaryStore) => ({
		...store,
		read: async (subject: string) => {
			reads += 1;
			return store.read(subject);
		},
	});
	const off = await boot(counted);
	await off.kept.records.create("alice", { sessions: now, erasedAt: now } as never, "endless");
	expect(await off.erasedSubjects.erased("alice")).toBe(false);
	expect(reads).toBe(0);
	const unread = await boot(counted, { unreadable: true });
	expect(await unread.erasedSubjects.erased("bob")).toBe(false);
	expect(reads).toBe(1);
	const on = await boot(counted, { on: true });
	await on.kept.records.create("alice", { sessions: now, erasedAt: now } as never, "endless");
	expect(await on.erasedSubjects.erased("alice")).toBe(true);
	expect(reads).toBe(2);
});
