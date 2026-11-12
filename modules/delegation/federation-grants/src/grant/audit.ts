import { type Audit, declaredAudit } from "@mod/audit";
import { isUnavailable } from "@mod/kernel";
import type { ErasedSubjects } from "@mod/subject-revocation";
import events from "../audit-events.ts";

/** The most characters of a text a caller sent that reach audit: federation-grants' own cap. */
const auditTextMax = 200;
/** Text a caller sent, cut short before it reaches audit. */
export const cut = (text: string) => text.slice(0, auditTextMax);

/** Records an event about a subject that may be erased, with the source where there is one. */
export type AuditedAbout = (
	kind: keyof typeof events,
	subject: string,
	attributes: Record<string, string>,
	source?: string,
) => Promise<void>;

/**
 * The one rule for an event about a subject that may be erased: named only where it is not; one
 * erased is withheld (`withheld` `erased`), one that cannot be read so too (`unread`). `erased`
 * tells what an audit names, never access.
 */
export function auditedAbout(audit: Audit, erased: ErasedSubjects): AuditedAbout {
	const audited = declaredAudit(audit, events);
	return async (kind, subject, attributes, source) => {
		const withheld = await erased.erased(subject).then(
			(is) => (is ? "erased" : undefined),
			(thrown: unknown) => {
				if (isUnavailable(thrown)) return "unread";
				throw thrown;
			},
		);
		const sourced = { ...attributes, ...(source ? { source } : {}) };
		audited.record(
			kind,
			withheld === undefined
				? { subject: cut(subject), attributes: sourced }
				: { attributes: { ...sourced, withheld } },
		);
	};
}
