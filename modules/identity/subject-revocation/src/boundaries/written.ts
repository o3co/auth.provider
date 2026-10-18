import { Unavailable } from "@mod/kernel";
import type { Write } from "../followers.ts";
import type { BoundaryStore, StoredBoundary } from "../store.ts";
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

/** Writes a subject's boundaries through the store at the time `now` gives. */
export function writtenTo(boundaries: BoundaryStore, now: () => number): Write {
	return async (subject, keep) => {
		const at = now();
		// Written even when far enough, so a boundary not yet confirmed is confirmed by this write.
		// A record that holds no time keeps nothing: both kinds move.
		const moved = (record: StoredBoundary) => {
			const held = opened(record);
			return stored(recorded(held, at, keep && held !== undefined));
		};
		// Update first: a subject revoked before then costs one call.
		if (await boundaries.update(subject, moved)) return;
		const first = stored(recorded(undefined, at, keep));
		if ((await boundaries.save(subject, first, "endless")) === "created") return;
		// Another request saved the first boundary meanwhile: move it from what it holds.
		if (!(await boundaries.update(subject, moved))) throw new Unavailable("subject-revocation");
	};
}
