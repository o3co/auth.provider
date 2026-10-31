import { type Audit, audit, declaredAudit } from "@mod/audit";
import { clientAllowance } from "@mod/client-allowance";
import { type Clients, clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route } from "@mod/http";
import { issuer } from "@mod/issuer";
import type { BuildContext } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { authenticateClient, oauthError } from "@mod/token-endpoint";
import { type AccessCheck, type Tokens, tokens } from "@mod/tokens";
import events from "../audit-events.ts";
import { tokenOf } from "../request.ts";

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

/** What `introspectionIn` takes. */
export const introspectionTakes = [clients, tokens, issuer, audit];

/** The introspection route's handler and its answer to Unavailable, which records it. */
/** The introspection handler over the contracts the assembly gives. */
export const introspectionIn = async (c: BuildContext<unknown>) =>
	introspection(
		await c.get(clients),
		await c.get(tokens),
		(await c.get(issuer)).url,
		await c.get(audit),
	);

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
		const token = tokenOf(request);
		if (typeof token !== "string") return token;
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
