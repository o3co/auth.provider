import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type BuildContext, Unavailable } from "@mod/kernel";
import type { RevocationFollower } from "@mod/subject-revocation";
import events from "../audit-events.ts";
import { type Grant, type Judge, type Records, withoutCredentials } from "../grant/grant.ts";
import { recordsOver, shared } from "../grant/shared.ts";
import type { Settings } from "../section.ts";
import { type GrantStore, grantStore, type SubjectGrants, subjectGrants } from "../store.ts";

export interface FollowParts {
	readonly grants: GrantStore;
	readonly subjects: SubjectGrants;
	readonly records: Records;
	/** The judge, once the composition is built: it reads the boundaries this follows. */
	readonly judge: () => Judge;
	readonly audit: Audit;
}

/**
 * Follows a subject's revocation through its listed grants, one at a time, writing now what the
 * boundary decides at the next read: a grant it covers, or a pending one whose intent it covers,
 * ends; an established grant it leaves loses only a renewal in flight. One that fails does not stop
 * the rest; the revocation is then told, and the boundary still refuses what is left.
 */
export function followerWith(p: FollowParts): RevocationFollower {
	const { records } = p;
	/** What the revocation makes of a grant as read: ended, its renewal ended, or left. */
	const verdict = async (grant: Grant) => {
		const judge = p.judge();
		const { intent } = grant;
		if (grant.status === "revoked") return "left";
		if (grant.authorizedAt !== undefined && (await judge.revoked(grant))) return "ended";
		if (!intent || !(await judge.intentRevoked(grant, intent))) return "left";
		return grant.status === "pending" ? "ended" : "renewal";
	};
	const follow = async (subject: string, id: string) => {
		const read = records.grantOf(await p.grants.read(id));
		const judged = read?.subject === subject ? await verdict(read) : "left";
		if (!read || judged === "left") {
			if (read?.subject !== subject || read.status === "revoked")
				await p.subjects.remove(subject, id);
			return;
		}
		const changed = await p.grants.change(id, (stored) => {
			const now = records.grantOf(stored);
			// Written only over the state judged, so a renewal or revocation since is left alone.
			if (!now || now.status === "revoked" || now.intent?.id !== read.intent?.id) return undefined;
			if (judged === "renewal" && now.intent && !now.intent.ended) {
				return {
					value: records.stored({ ...now, intent: { ...now.intent, ended: "subject_revoked" } }),
				};
			}
			if (judged !== "ended") return undefined;
			const ended: Grant = { ...withoutCredentials(now), status: "revoked", reason: "backstop" };
			return { value: records.stored(ended) };
		});
		const was = records.grantOf(changed?.before);
		const now = records.grantOf(changed?.after);
		if (now?.status !== "revoked") return;
		await p.subjects.remove(subject, id);
		if (was?.status === "revoked") return;
		declaredAudit(p.audit, events).record("federation.grant.revoked", {
			subject,
			attributes: { client: now.client, connection: now.connection, outcome: "backstop" },
		});
	};
	return {
		name: "federation-grants",
		follow: async (subject) => {
			let failed = 0;
			for (const { member } of await p.subjects.members(subject)) {
				await follow(subject, member).catch(() => {
					failed++;
				});
			}
			if (failed > 0) throw new Unavailable("federation-grants");
		},
	};
}

/** The follower over the contracts the assembly gives. */
export async function followerOver(c: BuildContext<Settings>) {
	// The shared parts read the revocations this follower is collected into: taken once built.
	const parts = c.late(shared);
	return followerWith({
		grants: await c.get(grantStore),
		subjects: await c.get(subjectGrants),
		records: await recordsOver(c),
		judge: () => parts().judge,
		audit: await c.get(audit),
	});
}
