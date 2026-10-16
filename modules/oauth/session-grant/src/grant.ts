import { clientAllowance } from "@mod/client-allowance";
import type { OriginEvidence } from "@mod/csrf";
import type { Grant, GrantOutcome } from "@mod/grants";
import type { Sessions } from "@mod/session";
import { type IssuedAccess, referenceOf, type Tokens } from "@mod/tokens";

export interface Parts {
	readonly evidence: OriginEvidence;
	readonly sessions: Sessions;
	readonly tokens: Tokens;
	readonly issuer: string;
}

const unauthorized: GrantOutcome = {
	kind: "error",
	error: "unauthorized",
	description: "session is not authenticated",
	status: 401,
};
const noLongerEntered: GrantOutcome = {
	kind: "error",
	error: "invalid_grant",
	description: "session_invalid",
};
const stepUp = (requirement: string): GrantOutcome => ({
	kind: "error",
	error: "invalid_grant",
	description: `the session must step up through ${requirement}`,
	members: { step_up: requirement },
});

export function sessionGrant(parts: Parts): Grant {
	// The token was never answered, so revoking only tidies up: its answer is not read.
	const revoke = (issued: IssuedAccess) => parts.tokens.revokeReferenced(referenceOf(issued));
	/**
	 * False, with the token revoked, when the session can no longer be entered (closed, expired or short)
	 * once the token is recorded. When the session cannot tell, the token is revoked too and the failure
	 * passed on.
	 */
	const keep = async (session: string, issued: IssuedAccess) => {
		let open: boolean;
		try {
			open = await parts.sessions.stillOpen(session);
		} catch (error) {
			// The session's failure is what the caller is told, whatever the revocation does.
			try {
				await revoke(issued);
			} catch {}
			throw error;
		}
		if (open) return true;
		await revoke(issued);
		return false;
	};

	return {
		grantType: "session",
		handle: async ({ request, client, param, issue }) => {
			// The cookie rides on requests from other sites too, so it alone proves nothing.
			if (!parts.evidence.sameOrigin(request)) return unauthorized;
			const entry = await parts.sessions.enterFor(request, "use");
			if (entry.kind === "absent") return unauthorized;
			if (entry.kind === "short") return stepUp(entry.requirement);
			const allowed = clientAllowance.allowedIssuance(client, param("scope"), parts.issuer);
			if (allowed.kind === "error") return allowed;
			const { session, endsAt } = entry;
			const { subject, amr, authenticatedAt, authenticatedAtUnknown } = session.context;
			const { scope, audience } = allowed;
			const access = {
				subject,
				issuedTo: client.id,
				scope,
				audience,
				amr,
				authenticatedAt,
				...(authenticatedAtUnknown ? { authenticatedAtUnknown } : {}),
			};
			// Nothing is used up before issuing, so `issue` alone asks the policies. The token never
			// outlives the session it comes from.
			const given = await issue(access, { session: session.id, notAfter: endsAt });
			if (given.kind === "refused") return given;
			const issued = given.access;
			if (!(await keep(session.id, issued))) return noLongerEntered;
			return {
				kind: "issued",
				body: {
					access_token: issued.token,
					token_type: issued.tokenType,
					expires_in: issued.expiresIn,
					...(scope.length > 0 ? { scope: scope.join(" ") } : {}),
				},
			};
		},
	};
}
