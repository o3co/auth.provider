import { type Audit, audit, declaredAudit } from "@mod/audit";
import { clientAllowance } from "@mod/client-allowance";
import type { Grant, GrantOutcome } from "@mod/grants";
import { issuer } from "@mod/issuer";
import type { BuildContext } from "@mod/kernel";
import { type Passkeys, passkeys } from "@mod/passkeys";
import { type Lineage, lineage } from "@mod/refresh";
import { type SubjectRevocation, subjectRevocation } from "@mod/subject-revocation";
import events from "../audit-events.ts";
import { passkeyAmr, webauthnGrantType } from "../contract.ts";

type Refusal = Extract<Awaited<ReturnType<Passkeys["assert"]>>, { kind: "refused" }>["reason"];

/** Each refusal of `passkeys`, as the audit records it. */
const reasons: Readonly<Record<Refusal, string>> = {
	malformed: "assertion_malformed",
	challenge: "challenge_invalid",
	origin: "origin_not_allowed",
	"top-origin": "top_origin_not_allowed",
	rp: "rp_mismatch",
	algorithm: "algorithm_not_allowed",
	signature: "signature_invalid",
	"sign-count": "sign_count_not_increased",
	"user-handle": "user_handle_mismatch",
	"user-verification": "user_verification_missing",
	"backup-eligibility": "backup_eligibility_changed",
	"unknown-credential": "credential_unknown",
	"no-user-handle": "user_handle_missing",
	raced: "sign_count_raced",
};

const invalidGrant = (description: string): GrantOutcome => ({
	kind: "error",
	error: "invalid_grant",
	description,
});

export interface LoginParts {
	readonly passkeys: Passkeys;
	readonly lineage: Lineage;
	readonly revocation: SubjectRevocation;
	readonly audit: Pick<Audit, "record">;
	readonly issuer: string;
}

/** What `passkeyGrantIn` takes from the build context. */
export const grantTakes = [passkeys, lineage, subjectRevocation, audit, issuer] as const;

/** The grant over the contracts the assembly gives. */
export const passkeyGrantIn = async (c: BuildContext<unknown>) =>
	passkeyGrant({
		passkeys: await c.get(passkeys),
		lineage: await c.get(lineage),
		revocation: await c.get(subjectRevocation),
		audit: await c.get(audit),
		issuer: (await c.get(issuer)).url,
	});

/** The passkey login grant: an assertion of a kept passkey for the client's tokens. */
export function passkeyGrant(p: LoginParts): Grant {
	return {
		grantType: webauthnGrantType,
		readsAmbient: "none",
		bodies: ["json"],
		handle: async ({ client, param, value, binding, issue }) => {
			// One answer for every refusal, so it never tells whether a credential is registered.
			const notAccepted = (reason: string) => {
				declaredAudit(p.audit, events).record("passkey.login.refused", {
					attributes: { client: client.id, reason },
				});
				return invalidGrant("passkey assertion not accepted");
			};
			const assertion = value("assertion");
			if (assertion === undefined) {
				return { kind: "error", error: "invalid_request", description: "assertion is required" };
			}
			if (typeof assertion !== "object" || assertion === null || Array.isArray(assertion)) {
				return invalidGrant("assertion must be an object");
			}
			const asserted = await p.passkeys.assert(assertion, client.id);
			if (asserted.kind === "refused") return notAccepted(reasons[asserted.reason]);
			// The authentication time is when the challenge was made.
			const { subject, challengedAt: authenticatedAt } = asserted;
			const allowed = clientAllowance.allowedIssuance(client, param("scope"), p.issuer);
			if (allowed.kind === "error") return allowed;
			const { scope, audience } = allowed;
			if ((await p.revocation.check(subject, authenticatedAt)) === "revoked") {
				return notAccepted("authentication_revoked");
			}
			const amr = passkeyAmr;
			// The holder is known only once `passkeys` has taken the challenge, so `issue` alone asks.
			// issue binds the access token itself; the family is handed the binding here.
			const issued = await issue({
				subject,
				issuedTo: client.id,
				audience,
				scope,
				amr,
				authenticatedAt,
			});
			if (issued.kind === "refused") return issued;
			const { access } = issued;
			const refreshToken = await p.lineage.start({
				client,
				subject,
				scope,
				audience,
				authenticatedAt,
				amr,
				...(binding ? { binding } : {}),
				access: { id: access.id, expiresAt: access.expiresAt },
			});
			return {
				kind: "issued",
				body: {
					access_token: access.token,
					token_type: access.tokenType,
					expires_in: access.expiresIn,
					...(refreshToken ? { refresh_token: refreshToken } : {}),
					scope: scope.join(" "),
				},
			};
		},
	};
}
