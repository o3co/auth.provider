import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import fc from "fast-check";
import { expect, it } from "vitest";
import { type BoundaryKind, revocations, subjectErasure } from "../src/contract.ts";
import revocationModule from "../src/module.ts";
import { boundaryStore, type StoredBoundary } from "../src/store.ts";
import { memoryBoundaries } from "./stores.ts";

const now = 1_800_000_000_000;
const subjects = ["alice", "bob"] as const;

const time = fc.integer({ min: now - 86_400_000, max: now + 86_400_000 });
/**
 * A record as another writer left it: 0.19's shapes, one of no time, one with a field of a later
 * format, and marked ones, readable or not, in records that open and in records that do not.
 */
const legacy = fc.oneof(
	time,
	fc.record({ sessions: time }),
	fc.record({ sessions: time, delegations: time }),
	fc.constant("no time"),
	fc.record({ sessions: time, later: fc.constant("a later format") }),
	fc.record({ sessions: time, delegations: fc.constant("a later format") }),
	fc.record({ sessions: time, erasedAt: time }),
	fc.record({ sessions: time, erasedAt: fc.constant("x") }),
	fc.record({ sessions: time, delegations: fc.constant("a later format"), erasedAt: time }),
);
type Step =
	| { readonly kind: "legacy"; readonly subject: string; readonly record: unknown }
	| { readonly kind: "revoke"; readonly subject: string; readonly keep: boolean }
	| { readonly kind: "mark"; readonly subject: string }
	| {
			readonly kind: "compare";
			readonly subject: string;
			readonly offsetMs: number;
			readonly boundary: BoundaryKind;
			readonly allowanceMs: number;
	  }
	| { readonly kind: "advance"; readonly ms: number };
const subject = fc.constantFrom(...subjects);
const step: fc.Arbitrary<Step> = fc.oneof(
	fc.record({ kind: fc.constant("legacy" as const), subject, record: legacy }),
	fc.record({ kind: fc.constant("revoke" as const), subject, keep: fc.boolean() }),
	fc.record({ kind: fc.constant("mark" as const), subject }),
	fc.record({
		kind: fc.constant("compare" as const),
		subject,
		offsetMs: fc.integer({ min: -86_400_000, max: 400 * 86_400_000 }),
		boundary: fc.constantFrom<BoundaryKind>("sessions", "delegations"),
		allowanceMs: fc.integer({ min: -1000, max: 86_400_000 }),
	}),
	fc.record({ kind: fc.constant("advance" as const), ms: fc.integer({ min: 1, max: 120_000 }) }),
);

/** Whether a stored record opens as boundaries: one time (0.19), or times with no field of another kind. */
const opens = (record: unknown) => {
	if (typeof record === "number") return true;
	if (typeof record !== "object" || record === null) return false;
	const { sessions, delegations, erasedAt } = record as Record<string, unknown>;
	const timeOrNone = (v: unknown) => v === undefined || typeof v === "number";
	return typeof sessions === "number" && timeOrNone(delegations) && timeOrNone(erasedAt);
};

/** What a stored record says of its mark: a time, one that is no time, or none. */
const markIn = (record: unknown) => {
	if (typeof record !== "object" || record === null || !("erasedAt" in record)) return undefined;
	return (record as { erasedAt: unknown }).erasedAt;
};
const boundariesIn = (record: unknown) =>
	typeof record === "object" && record !== null
		? {
				sessions: (record as { sessions?: unknown }).sessions,
				delegations: (record as { delegations?: unknown }).delegations,
			}
		: undefined;

/** An Unavailable is an answer (closed); any other error fails the run. */
const unavailableOnly = (error: unknown): undefined => {
	if (isUnavailable(error)) return undefined;
	throw error;
};

const runs = Number(process.env.FC_RUNS ?? 300);
const seed = Number(process.env.FC_SEED ?? 20261111);

it("keeps a subject's mark of erasure through every write of its boundary, and refuses the subject on every comparison from then; a write over a record it cannot open leaves it as it is where it holds a mark, and heals it where it holds none", async () => {
	await fc.assert(
		fc.asyncProperty(fc.array(step, { maxLength: 16 }), async (steps) => {
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
			const r = app.get(revocations);
			const erasure = app.get(subjectErasure);
			const read = (s: string): Promise<unknown> => stores.kept.records.read(s);
			const firstMark = new Map<string, number>();
			const everMarked = new Set<string>();

			for (const st of steps) {
				switch (st.kind) {
					case "legacy": {
						// Another writer's record, only where the subject holds none; a readable mark in it is the first.
						const created = await stores.kept.records.create(
							st.subject,
							st.record as unknown as StoredBoundary,
							"endless",
						);
						const mark = markIn(st.record);
						if (created === "created" && typeof mark === "number" && !firstMark.has(st.subject)) {
							firstMark.set(st.subject, mark);
						}
						break;
					}
					case "revoke": {
						const before = await read(st.subject);
						const done = await r.record(st.subject, { keepDelegations: st.keep }).then(
							() => true,
							(error: unknown) => unavailableOnly(error) ?? false,
						);
						const after = await read(st.subject);
						// Unavailable writes nothing.
						if (!done) expect(after, "a revocation left unavailable").toEqual(before);
						// A record that does not open, with a mark in it, is never written over.
						if (before !== undefined && !opens(before) && markIn(before) !== undefined) {
							expect(done, "a revocation over a mark it cannot open").toBe(false);
						}
						// One with no mark heals: fresh boundaries.
						if (before !== undefined && !opens(before) && markIn(before) === undefined) {
							expect(done && opens(after), "a revocation heals a record of no time").toBe(true);
						}
						break;
					}
					case "mark": {
						const before = await read(st.subject);
						const marked = await erasure.markErased(st.subject).catch(unavailableOnly);
						const after = await read(st.subject);
						if (marked === undefined) expect(after, "a mark left unavailable").toEqual(before);
						const held = markIn(before);
						// A readable mark is answered, and the record left exactly as it is, unknown fields too.
						if (typeof held === "number") {
							expect(marked?.erasedAt, "the mark a record holds").toBe(held);
							expect(after, "a marked record left as it is").toEqual(before);
						}
						// A mark that does not read is never written over.
						if (held !== undefined && typeof held !== "number") {
							expect(marked, "a mark over a mark it cannot read").toBeUndefined();
						}
						// A record of no time and no mark heals: a `sessions` boundary and the mark.
						if (before !== undefined && !opens(before) && held === undefined) {
							expect(
								marked !== undefined && opens(after) && typeof markIn(after) === "number",
								"a mark heals a record of no time",
							).toBe(true);
						}
						if (marked === undefined) break;
						const { erasedAt } = marked;
						const first = firstMark.get(st.subject);
						// The first readable mark is kept: every later mark answers it.
						if (first !== undefined) expect(erasedAt).toBe(first);
						else firstMark.set(st.subject, erasedAt);
						// The mark keeps the boundaries it finds, where they read as times.
						if (opens(before) && typeof before === "object") {
							expect(boundariesIn(after)).toEqual(boundariesIn(before));
						}
						break;
					}
					case "compare": {
						const answered = await r
							.compare(st.subject, now + st.offsetMs, st.boundary, st.allowanceMs)
							.catch((error: unknown) => {
								if (isUnavailable(error)) return "unavailable";
								throw error;
							});
						if (markIn(await read(st.subject)) !== undefined) expect(answered).not.toBe("valid");
						break;
					}
					case "advance":
						stores.advanceStore(st.ms);
						break;
				}

				for (const s of subjects) {
					const record = await read(s);
					const first = firstMark.get(s);
					// A readable mark stays as first written, whatever wrote the boundary since.
					if (first !== undefined) expect(markIn(record), `${s}'s mark`).toBe(first);
					// Once a record carries a mark, readable or not, no write drops it.
					if (markIn(record) !== undefined) everMarked.add(s);
					if (everMarked.has(s)) {
						expect(markIn(record), `${s}'s mark dropped`).not.toBeUndefined();
						for (const kind of ["sessions", "delegations"] as const) {
							const answered = await r
								.compare(s, now + 400 * 86_400_000, kind)
								.catch((error: unknown) => (isUnavailable(error) ? "unavailable" : error));
							expect(answered, `${s} compared on ${kind}`).not.toBe("valid");
						}
					}
				}
			}
		}),
		{ seed, numRuns: runs },
	);
}, 120_000);
