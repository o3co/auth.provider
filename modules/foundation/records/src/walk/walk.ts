import { Unavailable } from "@mod/kernel";
import type { Json } from "@mod/store";
import type { Place } from "../writing/writing.ts";

/**
 * A walk of a space by its declared name, as a maintenance tool hands it in, declared here by its
 * shape alone: `keys` are the store's, and `server` names the server a page ran on.
 */
export interface Walk {
	sweep(
		space: string,
		cursor?: string,
	): Promise<{
		readonly keys: readonly unknown[];
		readonly cursor?: string;
		readonly server: string;
	}>;
}

/** Why a walk did not finish: a server kept changing under it, the caller's signal, or the store. */
export type Unfinished = "walk-unsteady" | "aborted" | "unavailable";

/** A walk's answer: every record handed over, the visitor stopping it, or not finished, and why. */
export type Walked =
	| { readonly kind: "walked" }
	| { readonly kind: "stopped" }
	| { readonly kind: "unfinished"; readonly reason: Unfinished };

/** How many times a walk starts over on a changed server before it answers `walk-unsteady`. */
const walkRestarts = 8;

/**
 * Hands `visit` the value of each record the walk meets, a record met twice twice, until `visit`
 * answers false. A page from another server continues no walk: it starts over from the first page,
 * at most `walkRestarts` times. Values are read as the space's reads are, and never opened.
 */
export async function walkRecords(
	place: Place,
	walk: Walk,
	visit: (value: Json) => Promise<boolean> | boolean,
	signal?: AbortSignal,
): Promise<Walked> {
	const unfinished = (reason: Unfinished): Walked => ({ kind: "unfinished", reason });
	try {
		let cursor: string | undefined;
		let server: string | undefined;
		let started = 0;
		// Ends only after a page is taken with no cursor on: a start-over goes round again from the first page.
		for (;;) {
			if (signal?.aborted) return unfinished("aborted");
			const page = await walk.sweep(place.space.name, cursor);
			if (server !== undefined && page.server !== server) {
				started += 1;
				if (started > walkRestarts) return unfinished("walk-unsteady");
				server = page.server;
				cursor = undefined;
				continue;
			}
			server = page.server;
			for (const found of page.keys) {
				const key = recordKeyIn(found, place.space.name);
				if (key === undefined) continue;
				if (signal?.aborted) return unfinished("aborted");
				const { entry } = await place.store.get({
					space: place.space,
					partition: key,
					name: "record",
				});
				// Gone since the page was taken: nothing to hand over.
				if (!entry) continue;
				if (!(await visit(entry.value))) return { kind: "stopped" };
			}
			cursor = page.cursor;
			if (cursor === undefined) return { kind: "walked" };
		}
	} catch (error) {
		if (error instanceof Unavailable) return unfinished("unavailable");
		throw error;
	}
}

/** The key of a space's record a walk hands back, or none for another space, name or shape. */
function recordKeyIn(found: unknown, space: string): string | undefined {
	if (typeof found !== "object" || found === null) return undefined;
	const key = found as {
		readonly space?: { readonly name?: unknown };
		readonly partition?: unknown;
		readonly name?: unknown;
	};
	if (key.space?.name !== space || key.name !== "record" || typeof key.partition !== "string") {
		return undefined;
	}
	return key.partition;
}
