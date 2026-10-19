import { type Audit, declaredAudit } from "@mod/audit";
import type { Clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, noStore, type Route } from "@mod/http";
import { determinedSource } from "@mod/request-source";
import { authenticateClient, oauthError } from "@mod/token-endpoint";
import type { Tokens } from "@mod/tokens";
import events from "./audit-events.ts";
import type { RevocableKind } from "./contract.ts";

/** RFC 7009 §2.2: 200 with no body, whatever was or was not revoked. */
const answered: HttpResponse = { status: 200, headers: noStore };

export function accessKind(tokens: Tokens): RevocableKind {
	return {
		hint: "access_token",
		revoke: async (token, client) => {
			// Read past revocation, so a resend after an unconfirmed revocation writes again.
			const issued = await tokens.issuedToOf(token);
			if (issued.kind === "invalid") return "unknown";
			// Another client's token: nothing to do, and answered the same as a revocation.
			if (issued.issuedTo !== client.id) return "done";
			return (await tokens.revokeAccess(token)).kind === "unsupported" ? "unsupported" : "written";
		},
	};
}

/**
 * RFC 7009 revocation. Whatever the token is, the answer is the same unless revoking is
 * refused outright, so the answer tells a caller nothing about tokens it did not receive.
 * The hint only says which kind to try first (§2.1); a hint no kind answers to is ignored.
 */
export function revocation(
	clients: Clients,
	kinds: readonly RevocableKind[],
	audit: Audit,
): Pick<Route, "handle" | "unavailable"> {
	const answer = async (request: HttpRequest): Promise<HttpResponse> => {
		const authenticated = await authenticateClient(clients, request);
		if (authenticated.kind === "refused") return authenticated.response;
		if (request.form.repeated().length > 0) {
			return oauthError(400, "invalid_request", "repeated parameter");
		}
		const token = request.form.single("token");
		if (!token) return oauthError(400, "invalid_request", "token is required");
		const hint = request.form.single("token_type_hint");
		// The hinted kind first (§2.1); kinds are keyed by hint, so at most one matches.
		const ordered = [
			...kinds.filter((kind) => kind.hint === hint),
			...kinds.filter((kind) => kind.hint !== hint),
		];
		for (const kind of ordered) {
			const revoked = await kind.revoke(token, authenticated.client);
			switch (revoked) {
				case "unknown":
					continue;
				case "unsupported":
					return oauthError(400, "unsupported_token_type");
				case "written": {
					const source = determinedSource(request);
					declaredAudit(audit, events).record("token.revoked", {
						attributes: {
							client: authenticated.client.id,
							...(source === undefined ? {} : { source }),
							token_type: kind.hint,
						},
					});
					return answered;
				}
				case "done":
					return answered;
			}
		}
		return answered;
	};
	return { handle: answer, unavailable: { response: oauthError(503, "temporarily_unavailable") } };
}
