import type { Log } from "@mod/kernel";
import type { ClosingList, SubjectSessions } from "../../store.ts";

export interface ListingParts {
	readonly listed: SubjectSessions;
	readonly closings: ClosingList;
	readonly log: Log;
	/** What a session has left of the lifetime in force from its opening. */
	leftOf(handle: string): Promise<number>;
	/** Ends an open record there, calling no participants. */
	endOpen(handle: string): Promise<unknown>;
	close(handle: string): Promise<unknown>;
}

export interface Listing {
	/** Takes a closed session off its subject's listing; a failed removal is logged and passed. */
	unlist(subject: string, handle: string): Promise<void>;
	/** Closes what a login's listing pushed out; if the closings refuse, puts the listing back and throws. */
	closePushedOut(subject: string, opening: string, handles: readonly string[]): Promise<void>;
}

export function listingOver(parts: ListingParts): Listing {
	const { listed, closings, log } = parts;
	/** A closed session left listed costs only a later close, so a failed removal is logged and passed. */
	const unlist = async (subject: string, handle: string) => {
		try {
			await listed.remove(subject, handle);
		} catch (error) {
			log.warn("session-lifecycle.listing_failed", {
				step: "remove",
				kind: error instanceof Error ? error.name : typeof error,
			});
		}
	};
	/** Ends each open record there, calling no participants; how many it ended, and how many it could not. */
	const ended = async (handles: readonly string[]) => {
		const counts = { ended: 0, lost: 0 };
		for (const handle of handles) {
			try {
				await parts.endOpen(handle);
				counts.ended++;
			} catch {
				counts.lost++;
			}
		}
		return counts;
	};
	/**
	 * Lists a pushed-out session again for what it has left. One that cannot be listed, and any the
	 * listing pushes out to take it back, is ended in its record, so none stays open unlisted.
	 */
	const putBack = async (subject: string, handle: string) => {
		let pushedOut: readonly string[];
		try {
			const left = await parts.leftOf(handle);
			if (left <= 0) return { ended: 0, lost: 0 };
			({ pushedOut } = await listed.add(subject, handle, left));
		} catch {
			return ended([handle]);
		}
		return ended(pushedOut);
	};
	/** Closes what a login's listing pushed out, each kept as a closing first, so the sweep finishes one that fails here; if the closings refuse, the listing is put back (each for what it has left, so it still ends first) and the login fails. */
	const closePushedOut = async (subject: string, opening: string, handles: readonly string[]) => {
		log.warn("session-lifecycle.listing_pushed_out", { count: handles.length });
		try {
			for (const handle of handles) await closings.add(handle);
		} catch (error) {
			await listed.remove(subject, opening).catch(() => undefined);
			const total = { ended: 0, lost: 0 };
			for (const handle of handles) {
				const counts = await putBack(subject, handle);
				total.ended += counts.ended;
				total.lost += counts.lost;
			}
			if (total.ended > 0) log.warn("session-lifecycle.listing_ended", { count: total.ended });
			if (total.lost > 0)
				log.warn("session-lifecycle.listing_put_back_failed", { count: total.lost });
			throw error;
		}
		for (const handle of handles) {
			try {
				await parts.close(handle);
			} catch {}
		}
	};
	return { unlist, closePushedOut };
}
