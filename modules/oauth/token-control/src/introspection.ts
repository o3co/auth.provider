import { type Audit, declaredAudit } from "@mod/audit";
import { clientAllowance } from "@mod/client-allowance";
import type { Clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route } from "@mod/http";
import { determinedSource } from "@mod/request-source";
import { authenticateClient, oauthError } from "@mod/token-endpoint";
import type { AccessCheck, Tokens } from "@mod/tokens";
import events from "./audit-events.ts";

const inactive: HttpResponse = jsonAnswer(200, { active: false });

type Valid = Extract<AccessCheck, { kind: "valid" }>;

/** RFC 7662 §2.2 members for an active token; `cnf` only for a bound one. */
function activeAnswer(issuer: string, checked: Valid): HttpResponse {
	const { grant } = checked;
	return jsonAnswer(200, {
		active: true,
		iss: issuer,
		sub: grant.subject,
		client_id: grant.issuedTo,
		aud: grant.audience.length === 1 ? grant.audience[0] : grant.audience,
		...(grant.scope.length > 0 ? { scope: grant.scope.join(" ") } : {}),
		exp: Math.floor(checked.expiresAt / 1000),
		token_type: checked.tokenType,
		...(checked.binding ? { cnf: { [checked.binding.member]: checked.binding.confirmation } } : {}),
	});
}

/** The introspection route's handler and its answer to Unavailable, which records it. */
export function introspection(
	clients: Clients,
	tokens: Tokens,
	issuer: string,
	audit: Audit,
): Pick<Route, "handle" | "unavailable"> {
	const answer = async (request: HttpRequest): Promise<HttpResponse> => {
		const authenticated = await authenticateClient(clients, request, audit);
		if (authenticated.kind === "refused") return authenticated.response;
		const caller = authenticated.client;
		if (caller.kind !== "confidential")
			return oauthError(401, "invalid_client", "public clients may not introspect");
		if (request.form.repeated().length > 0) {
			return oauthError(400, "invalid_request", "repeated parameter");
		}
		const token = request.form.single("token");
		if (!token) return oauthError(400, "invalid_request", "token is required");
		const checked = await tokens.verifyAccess(token);
		if (checked.kind === "invalid" || !clientAllowance.maySee(caller, checked.grant.audience)) {
			return inactive;
		}
		return activeAnswer(issuer, checked);
	};
	return {
		handle: answer,
		unavailable: {
			response: oauthError(503, "temporarily_unavailable"),
			noted: (request) => {
				const source = determinedSource(request);
				declaredAudit(audit, events).record("introspection.unavailable", {
					attributes: source === undefined ? {} : { source },
				});
			},
		},
	};
}
