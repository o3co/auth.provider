import { type BuildContext, contract, type Log } from "@mod/kernel";
import { type Grant, type Judge, withoutCredentials } from "../grant/grant.ts";
import { shared } from "../grant/shared.ts";
import type { Settings } from "../section.ts";
import { type SubjectGrants, subjectGrants } from "../store.ts";

/** Takes a grant off its subject's listing; a failed write is logged and passed, as a listing's is. */
export function unlistingWith(subjects: SubjectGrants, log: Log) {
	return async (grant: Grant) => {
		try {
			await subjects.remove(grant.subject, grant.id);
		} catch (error) {
			const kind = error instanceof Error ? error.name : typeof error;
			log.warn("federation-grants.listing_failed", { kind });
		}
	};
}

export type Unlisting = ReturnType<typeof unlistingWith>;

/**
 * A grant revoked for `reason` at `now`, without its credentials, and how long its record is then
 * kept: `retentionMs` past the earlier of the revocation and its end (its intent's, never
 * connected), so one revoked past its end is never kept longer for it.
 */
export function revocationWith(judge: Judge, retentionMs: number) {
	return (grant: Grant, reason: "client" | "backstop", now: number) => {
		const end = judge.endOf(grant) ?? grant.intent?.endsAt ?? now;
		const revoked: Grant = { ...withoutCredentials(grant), status: "revoked", reason };
		return { grant: revoked, lifetimeMs: Math.max(1, Math.min(now, end) + retentionMs - now) };
	};
}

export type Revocation = ReturnType<typeof revocationWith>;

/** The revoked rewrite and the unlisting, built once over the shared parts. */
export const retention = contract<{
	readonly revocation: Revocation;
	readonly unlisted: Unlisting;
}>("federation-grants.retention");

/** What `retentionOver` takes besides the shared parts. */
export const retentionTakes = [subjectGrants] as const;

/** The revocation over the shared judge and the section's `retention`, and the unlisting over the listing. */
export async function retentionOver(c: BuildContext<Settings>) {
	const { judge } = await c.get(shared);
	return {
		revocation: revocationWith(judge, c.section.retention * 1000),
		unlisted: unlistingWith(await c.get(subjectGrants), c.log),
	};
}
