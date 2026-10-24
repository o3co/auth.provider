import { type Audit, audit, declaredAudit } from "@mod/audit";
import type { HttpRequest } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import events from "../audit-events.ts";

/** What a passkey login and the gate record, with the source where `request-source` determined it. */
export function recordedOver(recorder: Pick<Audit, "record">) {
	const audited = declaredAudit(recorder, events);
	const sourced = (request: HttpRequest) => {
		const source = determinedSource(request);
		return source === undefined ? {} : { source };
	};
	return {
		session: (
			request: HttpRequest,
			kind: "opened" | "held" | "refused",
			subject?: string,
			reason?: string,
		) =>
			audited.record(`passkey.session.${kind}`, {
				...(subject === undefined ? {} : { subject }),
				attributes: { ...(reason === undefined ? {} : { reason }), ...sourced(request) },
			}),
		passwordRefused: (request: HttpRequest, subject: string) =>
			audited.record("passkey.password_refused", { subject, attributes: sourced(request) }),
	};
}

export type Recorded = ReturnType<typeof recordedOver>;

export const recordedIn = async (c: BuildContext<unknown>) => recordedOver(await c.get(audit));
