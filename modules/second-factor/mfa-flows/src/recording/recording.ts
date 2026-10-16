import { type Audit, declaredAudit } from "@mod/audit";
import type { HttpRequest } from "@mod/http";
import { determinedSource } from "@mod/request-source";
import events from "../audit-events.ts";

/** The source as an audit attribute, only when request-source determined it. */
const sourceOf = (request: HttpRequest): { source?: string } => {
	const source = determinedSource(request);
	return source === undefined ? {} : { source };
};
type Declared<K> = K extends `mfa.${infer Kind}` ? Kind : never;
/** Records `mfa.<kind>` as declared, with the source when request-source determined it. */
export const auditedBy = (audit: Pick<Audit, "record">) => {
	const audited = declaredAudit(audit, events);
	return (
		kind: Declared<keyof typeof events>,
		subject: string,
		request: HttpRequest,
		attributes: Record<string, string>,
	) =>
		audited.record(`mfa.${kind}`, {
			subject,
			attributes: { ...attributes, ...sourceOf(request) },
		});
};
