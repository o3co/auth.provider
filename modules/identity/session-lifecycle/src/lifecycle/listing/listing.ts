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
	/** Lists a pushed-out session again for what it has left; one that cannot be is ended in its record, so none stays open unlisted. */
	const putBack = async (subject: string, handle: string) => {
		try {
			const left = await parts.leftOf(handle);
			if (left > 0) await listed.add(subject, handle, left);
		} catch {
			await parts.endOpen(handle);
		}
	};
	/** Closes what a login's listing pushed out, each kept as a closing first, so the sweep finishes one that fails here; if the closings refuse, the listing is put back (each for what it has left, so it still ends first) and the login fails. */
	const closePushedOut = async (subject: string, opening: string, handles: readonly string[]) => {
		log.warn("session-lifecycle.listing_pushed_out", { count: handles.length });
		try {
			for (const handle of handles) await closings.add(handle);
		} catch (error) {
			await listed.remove(subject, opening).catch(() => undefined);
			let lost = 0;
			for (const handle of handles) await putBack(subject, handle).catch(() => lost++);
			if (lost > 0) log.warn("session-lifecycle.listing_put_back_failed", { count: lost });
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
