import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable, type Log, Unavailable } from "@mod/kernel";
import type { EnrollmentWitness } from "@mod/mfa-witness";
import events from "../audit-events.ts";

import type { Asked } from "../contract.ts";

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
