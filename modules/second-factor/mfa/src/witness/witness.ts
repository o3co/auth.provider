import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { EnrollmentWitness } from "@mod/mfa-witness";
import events from "../audit-events.ts";

import type { Asked, Witnessing } from "../contract.ts";

export interface StandingParts {
	/** None composed leaves the store alone to tell. */
	readonly witness: EnrollmentWitness | undefined;
	readonly audit: Pick<Audit, "record">;
	readonly log: Pick<Log, "warn">;
}

/**
 * Whether a subject's counting factors stand for its enrollment: `held`, or `none` where the witness
 * marks nothing either. Where it marks a subject holding none, the store may have lost them: that is
 * recorded and unavailable, never none. A witness that cannot be read is unavailable too.
 */
export function standingOf(p: StandingParts) {
	const audited = declaredAudit(p.audit, events);
	return async (subject: string, counts: boolean, at: Asked) => {
		if (counts) return "held" as const;
		if (p.witness === undefined || !(await p.witness.read(subject))) return "none" as const;
		audited.record("mfa.enrollment_inconsistent", { subject, attributes: { at } });
		p.log.warn("mfa.enrollment_inconsistent", { at });
		throw new Unavailable("mfa");
	};
}

/** A witness unavailable is asked again this often, with the same token, which answers alike. */
const enrollRetries = 3;

/** Whether the witness's mark is `token`'s, asked again while it is unavailable. */
export async function markedBy(witness: EnrollmentWitness, subject: string, token: string) {
	for (let attempt = 0; ; attempt++) {
		try {
			return await witness.enroll(subject, token);
		} catch (error) {
			if (!isUnavailable(error) || attempt === enrollRetries) throw error;
		}
	}
}

export interface SettlingParts {
	/** None composed leaves nothing to settle. */
	readonly witness: EnrollmentWitness | undefined;
	/** Whether the subject holds a counting factor, as written now. */
	readonly counting: () => Promise<boolean>;
	/** A new token for a mark this call sets. */
	readonly token: () => string;
}

/**
 * Brings the witness's mark in line with the subject's counting factors after a write: a factor
 * with no mark is marked; a mark with nothing counting goes only where this call set it (a reset
 * took the factor meanwhile), as any other may be a store that lost its factors. Read again after
 * each change, it settles twice at most, then is unavailable while they still differ.
 */
export function settlingOf(p: SettlingParts) {
	return async (subject: string) => {
		const witness = p.witness;
		if (witness === undefined) return;
		let set = false;
		for (let round = 0; round < 3; round++) {
			const counts = await p.counting();
			const marked = await witness.read(subject);
			if (counts === marked) return;
			if (round === 2) break;
			if (counts) {
				set = (await markedBy(witness, subject, p.token())) || set;
			} else if (set) {
				await witness.clear(subject);
			} else {
				return;
			}
		}
		throw new Unavailable("mfa");
	};
}

/** The witnessing over a witness composed beside mfa itself, for an app that does not compose `mfa-witnessing`. */
export function witnessingOver(
	p: StandingParts & { readonly token: () => string },
): Witnessing | undefined {
	const witness = p.witness;
	if (witness === undefined) return undefined;
	const standing = standingOf(p);
	return {
		standing: async (subject, counts, at) => standing(subject, counts, at),
		settle: (subject, counting) => settlingOf({ witness, counting, token: p.token })(subject),
		cleared: (subject) => witness.clear(subject),
	};
}
