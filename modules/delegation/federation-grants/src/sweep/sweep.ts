import type { Audit } from "@mod/audit";
import type { BuildContext, Clock, Log, Random } from "@mod/kernel";
import { type ErasedSubjects, erasedSubjects } from "@mod/subject-revocation";
import { auditedAbout } from "../grant/audit.ts";
import {
	type Grant,
	type Judge,
	type Records,
	secretFrom,
	withoutCredentials,
} from "../grant/grant.ts";
import type { Revocation, Unlisting } from "../retention/retention.ts";
import type { Settings } from "../section.ts";
import { type GrantStore, grantStore } from "../store.ts";

export interface SweepParts {
	readonly grants: GrantStore;
	readonly records: Records;
	readonly judge: Judge;
	readonly revocation: Revocation;
	readonly unlisted: Unlisting;
	readonly audit: Audit;
	/** Whether a subject is marked erased: for what an audit names, never for access. */
	readonly erased: ErasedSubjects;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
}

/**
 * One pass over every grant kept: the credentials of one past its end, or of one its subject's
 * revocation ends, are erased though no request reads it. A pass that cannot read a page stops,
 * and the next starts again from the first.
 */
export function sweepWith(p: SweepParts) {
	const { grants, records, judge } = p;
	const version = secretFrom(p.random);
	const about = auditedAbout(p.audit, p.erased);
	const ended = (grant: Grant) => {
		const end = judge.endOf(grant);
		return end !== undefined && end <= p.clock.now();
	};
	/** Erases a grant past its end, judged again on the record as written, under a new version. */
	const lapse = (id: string) =>
		grants.change(id, (stored) => {
			const now = records.grantOf(stored);
			if (!now?.sealed || !ended(now)) return undefined;
			return { value: records.stored({ ...withoutCredentials(now), version: version() }) };
		});
	/**
	 * Revokes a grant its subject's revocation ends: judged outside the write, which binds the
	 * judgement to the subject and the authorization it was made on. Answers whether it wrote.
	 */
	const revoke = async (id: string, judged: Grant) => {
		const at = p.clock.now();
		const changed = await grants.change(id, (stored) => {
			const now = records.grantOf(stored);
			if (!now?.sealed || now.status === "revoked") return undefined;
			if (now.subject !== judged.subject || now.authorizedAt !== judged.authorizedAt)
				return undefined;
			const revoked = p.revocation(now, "backstop", at);
			return { value: records.stored(revoked.grant), lifetimeMs: revoked.lifetimeMs };
		});
		const after = records.grantOf(changed?.after);
		if (records.grantOf(changed?.before)?.status === "revoked" || after?.status !== "revoked")
			return false;
		await p.unlisted(after);
		// Revoked because its subject's boundary ends it, erasure among the reasons: audited without it where so.
		const attributes = { client: after.client, connection: after.connection, outcome: "backstop" };
		await about("federation.grant.revoked", after.subject, attributes);
		return true;
	};
	/** Sweeps one grant; a grant authorized again since the judgement is read and judged once more. */
	const one = async (id: string) => {
		for (let tries = 0; tries < 2; tries++) {
			const grant = records.grantOf(await grants.read(id));
			if (!grant?.sealed) return;
			if (ended(grant)) {
				await lapse(id);
				return;
			}
			if (!(await judge.revoked(grant))) return;
			if (await revoke(id, grant)) return;
		}
	};
	return async (stopping: AbortSignal) => {
		let failed = 0;
		let cursor: string | undefined;
		do {
			if (stopping.aborted) return;
			let page: Awaited<ReturnType<GrantStore["scan"]>>;
			try {
				page = await grants.scan(cursor);
			} catch {
				// The pass is not done: the next starts again from the first page.
				p.log.warn("federation-grants.sweep_incomplete", {});
				return;
			}
			for (const id of page.keys) {
				if (stopping.aborted) return;
				await one(id).catch(() => {
					failed++;
				});
			}
			cursor = page.cursor;
		} while (cursor !== undefined);
		if (failed > 0) p.log.warn("federation-grants.sweep_failed", { count: failed });
	};
}

export const sweepTakes = [grantStore, erasedSubjects] as const;

/** Starts the sweep on this host every `sweep-interval`, over the contracts the assembly gives. */
export async function sweepIn(
	c: BuildContext<Settings>,
	parts: Pick<SweepParts, "records" | "judge" | "revocation" | "unlisted">,
	audit: Audit,
) {
	const sweep = sweepWith({
		grants: await c.get(grantStore),
		...parts,
		audit,
		erased: await c.get(erasedSubjects),
		clock: c.clock,
		random: c.random,
		log: c.log,
	});
	c.every(c.section["sweep-interval"] * 1000, sweep);
}
