import { Unavailable } from "@mod/kernel";
import type { ErasedSubjects } from "../contract.ts";
import type { Write } from "../followers.ts";
import type { BoundaryStore, BoundaryWrite, StoredBoundary } from "../store.ts";
import { type Boundaries, recorded } from "./boundaries.ts";

export const stored = (boundaries: Boundaries) => boundaries as unknown as StoredBoundary;

/**
 * The boundaries a record holds (one time is the earlier shape, for both kinds), or none when it
 * holds no time or a mark of erasure that is no time.
 */
export const opened = (record: StoredBoundary): Boundaries | undefined => {
	const value: unknown = record;
	if (typeof value === "number") return { sessions: value, delegations: value };
	if (typeof value !== "object" || value === null) return undefined;
	const { sessions, delegations, erasedAt } = value as Record<string, unknown>;
	if (typeof sessions !== "number") return undefined;
	if (delegations !== undefined && typeof delegations !== "number") return undefined;
	if (erasedAt !== undefined && typeof erasedAt !== "number") return undefined;
	return {
		sessions,
		...(delegations === undefined ? {} : { delegations }),
		...(erasedAt === undefined ? {} : { erasedAt }),
	};
};

/** The mark of erasure a record carries as it is stored, readable or not; none where it carries none. */
export const markIn = (record: StoredBoundary): unknown => {
	const value: unknown = record;
	if (typeof value !== "object" || value === null) return undefined;
	return (value as { readonly erasedAt?: unknown }).erasedAt;
};

/** `erased` where the record the committed write read carried a mark of a time; none otherwise. */
const erasedAnswer = (before: StoredBoundary): { readonly erased?: true } =>
	typeof markIn(before) === "number" ? { erased: true } : {};

/**
 * Whether a subject is marked erased, by the mark its record carries, read on every call and never
 * through the enabled reading: a mark of a time, whatever else the record holds, is erased.
 */
export function erasedIn(boundaries: BoundaryStore): ErasedSubjects["erased"] {
	return async (subject) => {
		const record = await boundaries.read(subject);
		const mark = record === undefined ? undefined : markIn(record);
		if (mark === undefined) return false;
		if (typeof mark !== "number") throw new Unavailable("subject-revocation");
		return true;
	};
}

/** The deadline a store hands a write; one that hands none, or one of no number, has written nothing it can confirm. */
export const timeOf = (write: BoundaryWrite | undefined) => {
	const deadline: unknown = write?.deadline;
	if (typeof deadline !== "number" || !Number.isFinite(deadline)) {
		throw new Unavailable("subject-revocation");
	}
	return deadline;
};

/**
 * Writes a subject's boundaries through the store at the deadline of the write that records them,
 * on the store's clock, so a boundary is never earlier than the time its write became visible.
 */
export function writtenTo(boundaries: BoundaryStore): Write {
	return async (subject, keep) => {
		// Written even when far enough, so a boundary not yet confirmed is confirmed by this write.
		// A record that holds no time keeps nothing: both kinds move.
		const moved = (record: StoredBoundary, write: BoundaryWrite) => {
			const held = opened(record);
			// A mark of erasure that cannot be read is never written over: the mark stays for good.
			if (held === undefined && markIn(record) !== undefined)
				throw new Unavailable("subject-revocation");
			return stored(recorded(held, timeOf(write), keep && held !== undefined));
		};
		// Update first: a subject revoked before then costs one call.
		const updated = await boundaries.update(subject, moved);
		if (updated) return erasedAnswer(updated.before);
		const first = (write: BoundaryWrite) => stored(recorded(undefined, timeOf(write), keep));
		if ((await boundaries.save(subject, first, "endless")) === "created") return {};
		// Another request saved the first boundary meanwhile: move it from what it holds.
		const raced = await boundaries.update(subject, moved);
		if (!raced) throw new Unavailable("subject-revocation");
		return erasedAnswer(raced.before);
	};
}
