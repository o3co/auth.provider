import { type Clock, isUnavailable } from "@mod/kernel";
import {
	DestinationRefused,
	jsonObjectOf,
	type Outbound,
	type OutboundResponse,
} from "@mod/outbound";
import type { JwksSource } from "./contract.ts";
import { type Candidate, fromJwk } from "./keys.ts";

/** A set is used this long after it was fetched. */
const holdMs = 3_600_000;
/** Fetches, whether they worked or not, are at least this far apart. */
const spacingMs = 60_000;

/**
 * The key set at a URL: fetched when first needed, kept an hour, fetched again at most once a minute,
 * and past `maxAgeMs` after it was fetched never used.
 */
export function jwksAt(
	source: JwksSource,
	deps: { readonly clock: Clock; readonly outbound: Outbound; readonly maxAgeMs: number },
) {
	const { clock } = deps;
	let kept: { readonly keys: readonly Candidate[]; readonly fetchedAt: number } | undefined;
	let tried: number | undefined;
	let fetching: Promise<void> | undefined;

	const fetchAndKeep = async () => {
		// The set's age counts from the start, however long the answer takes.
		const began = clock.now();
		tried = began;
		let response: OutboundResponse;
		try {
			response = await deps.outbound.fetch(
				source.url,
				{ headers: { accept: "application/json" } },
				{ hosts: source.hosts },
			);
		} catch (error) {
			if (isUnavailable(error) || error instanceof DestinationRefused) return;
			throw error;
		}
		const answer = jsonObjectOf(response);
		const listed = answer.kind === "object" ? answer.value.keys : undefined;
		if (!Array.isArray(listed)) return;
		const keys = listed.flatMap((jwk) =>
			jwk && typeof jwk === "object" && !Array.isArray(jwk) ? (fromJwk(jwk) ?? []) : [],
		);
		kept = { keys, fetchedAt: began };
	};
	/** One fetch at a time, shared by every check that waits for it, and none within a minute of the last. */
	const refresh = async () => {
		if (!fetching && (tried === undefined || clock.now() - tried >= spacingMs)) {
			fetching = fetchAndKeep().finally(() => {
				fetching = undefined;
			});
		}
		await fetching;
	};
	/** The kept set while it is young enough to use, even when it cannot be renewed. */
	const usable = () =>
		kept && clock.now() - kept.fetchedAt < deps.maxAgeMs ? kept.keys : undefined;
	return {
		/** The set to check with: the kept one while it holds, else a fresh one where it can be had, else the last. */
		keys: async (): Promise<readonly Candidate[] | undefined> => {
			if (!kept || clock.now() - kept.fetchedAt >= holdMs) await refresh();
			return usable();
		},
		/** A fresh set for a key the kept one lacks, where a fetch is due. */
		again: async (): Promise<readonly Candidate[] | undefined> => {
			await refresh();
			return usable();
		},
	};
}

/** A key set at a URL, as one composition keeps it. */
export type KeySet = ReturnType<typeof jwksAt>;
