import { Unavailable } from "@mod/kernel";
import type { Write } from "../followers.ts";
import type { BoundaryStore, BoundaryWrite, StoredBoundary } from "../store.ts";
import { type Boundaries, recorded } from "./boundaries.ts";

const stored = (boundaries: Boundaries) => boundaries as unknown as StoredBoundary;

/** The boundaries a record holds (one time is the earlier shape, for both kinds), or none when it holds no time. */
export const opened = (record: StoredBoundary): Boundaries | undefined => {
	const value: unknown = record;
	if (typeof value === "number") return { sessions: value, delegations: value };
	if (typeof value !== "object" || value === null) return undefined;
	const { sessions, delegations } = value as { sessions?: unknown; delegations?: unknown };
	if (typeof sessions !== "number") return undefined;
	if (delegations === undefined) return { sessions };
	return typeof delegations === "number" ? { sessions, delegations } : undefined;
};

/**
 * Writes a subject's boundaries through the store at the deadline of the write that records them,
 * on the store's clock, so a boundary is never earlier than the time its write became visible;
 * the time `now` gives stands in only where a store hands no write.
 */
export function writtenTo(boundaries: BoundaryStore, now: () => number): Write {
	return async (subject, keep) => {
		const at = now();
		const timeOf = (write?: BoundaryWrite) => write?.deadline ?? at;
		// Written even when far enough, so a boundary not yet confirmed is confirmed by this write.
		// A record that holds no time keeps nothing: both kinds move.
		const moved = (record: StoredBoundary, write?: BoundaryWrite) => {
			const held = opened(record);
			return stored(recorded(held, timeOf(write), keep && held !== undefined));
		};
		// Update first: a subject revoked before then costs one call.
		if (await boundaries.update(subject, moved)) return;
		const first = (write?: BoundaryWrite) => stored(recorded(undefined, timeOf(write), keep));
		if ((await boundaries.save(subject, first, "endless")) === "created") return;
		// Another request saved the first boundary meanwhile: move it from what it holds.
		if (!(await boundaries.update(subject, moved))) throw new Unavailable("subject-revocation");
	};
}
