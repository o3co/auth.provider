import { declaredAudit } from "@mod/audit";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { determinedSource } from "@mod/request-source";
import events from "../audit-events.ts";
import { auditedAbout, cut } from "../grant/audit.ts";
import { connectionsIn, type Grant, secretFrom } from "../grant/grant.ts";
import type { ApiParts } from "./api.ts";

export const error = (
	status: number,
	code: string,
	description?: string,
	headers?: Record<string, string>,
) =>
	jsonAnswer(
		status,
		{ error: code, ...(description ? { error_description: description } : {}) },
		headers ? { headers } : {},
	);

/** What every client route works with: the parts, a secret, the connections, the audit, and a grant's own refusal. */
export function apiCommonWith(p: ApiParts) {
	const { records, settings } = p;
	const secret = secretFrom(p.random);
	const connections = connectionsIn(settings, p.upstreams);
	const audited = declaredAudit(p.audit, events);
	const record = (
		kind: keyof typeof events,
		subject: string | undefined,
		attributes: Record<string, string>,
		request: HttpRequest,
	) => {
		const from = determinedSource(request);
		audited.record(kind, {
			...(subject === undefined ? {} : { subject: cut(subject) }),
			attributes: { ...attributes, ...(from ? { source: from } : {}) },
		});
	};
	const about = auditedAbout(p.audit, p.erased);
	/** Records an event about a subject that may be erased, as `grant`'s one rule has it. */
	const recordAbout = (
		kind: keyof typeof events,
		subject: string,
		attributes: Record<string, string>,
		request: HttpRequest,
	) => about(kind, subject, attributes, determinedSource(request));
	/** What a grant's own record says before anything is asked of it, as every grant route answers it, and why. */
	const stateRefusal = (
		grant: Grant,
	): { readonly why: string; readonly answer: HttpResponse } | undefined => {
		if (grant.status === "revoked")
			return { why: "grant_revoked", answer: error(410, "grant_revoked", grant.reason) };
		if (grant.status === "pending")
			return { why: "authorization_pending", answer: error(400, "authorization_pending") };
		const end = p.judge.endOf(grant);
		if (end !== undefined && end <= p.clock.now())
			return { why: "grant_expired", answer: error(410, "grant_expired", "lifetime") };
		return undefined;
	};
	return { p, records, settings, secret, connections, record, recordAbout, stateRefusal };
}

export type ApiCommon = ReturnType<typeof apiCommonWith>;
