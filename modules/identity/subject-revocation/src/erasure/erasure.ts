import { Unavailable } from "@mod/kernel";
import { recorded } from "../boundaries/boundaries.ts";
import { opened, stored, timeOf } from "../boundaries/written.ts";
import type { SubjectErasure } from "../contract.ts";
import type { BoundaryStore, BoundaryWrite, StoredBoundary } from "../store.ts";

/** The erasure's mark, read from what a write answered; a store that answered no mark wrote none. */
const markOf = (record: StoredBoundary) => {
	const erasedAt = opened(record)?.erasedAt;
	if (erasedAt === undefined) throw new Unavailable("subject-revocation");
	return erasedAt;
};

/**
 * Marks subjects erased through the store at the deadline of the write that marks them, as
 * boundaries are written: the boundaries kept, the first mark kept.
 */
export function markedIn(boundaries: BoundaryStore): SubjectErasure["markErased"] {
	// A record that holds no time keeps nothing: the mark comes with a `sessions` boundary at its time.
	const marked = (record: StoredBoundary | undefined, write: BoundaryWrite) => {
		const held = record === undefined ? undefined : opened(record);
		const at = timeOf(write);
		const kept = held ?? recorded(undefined, at, true);
		return stored({ ...kept, erasedAt: held?.erasedAt ?? at });
	};
	return async (subject) => {
		const changed = await boundaries.update(subject, marked);
		if (changed) return { kind: "marked", erasedAt: markOf(changed.after) };
		if (
			(await boundaries.save(subject, (write) => marked(undefined, write), "endless")) === "exists"
		) {
			// Another request saved the first boundary meanwhile: mark it from what it holds.
			const again = await boundaries.update(subject, marked);
			if (!again) throw new Unavailable("subject-revocation");
			return { kind: "marked", erasedAt: markOf(again.after) };
		}
		const saved = await boundaries.read(subject);
		if (saved === undefined) throw new Unavailable("subject-revocation");
		return { kind: "marked", erasedAt: markOf(saved) };
	};
}
