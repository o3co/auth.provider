import { type Audit, declaredAudit } from "@mod/audit";
import { jsonAnswer, type Route } from "@mod/http";
import { isLabel } from "@mod/labels";
import type { RegistrationRefusal, Registrations } from "@mod/passkeys";
import type { SubjectRevocation } from "@mod/subject-revocation";
import events from "../audit-events.ts";
import { type Exchange, invalid, sourced } from "../exchange/exchange.ts";

export interface RegisteringParts {
	readonly exchange: Exchange;
	readonly registrations: Registrations;
	/** Whether the subject was revoked after a time: a passkey registered meanwhile is ended. */
	readonly revocation: Pick<SubjectRevocation, "check">;
	readonly audit: Audit;
}

/** Each refusal in the words clients of these routes know; `revoked`, a registration a revocation reached, is answered as no session. */
const errorOf: Record<RegistrationRefusal | "revoked", string> = {
	origin: "origin_mismatch",
	"top-origin": "top_origin_mismatch",
	challenge: "challenge_mismatch",
	rp: "rp_id_mismatch",
	algorithm: "algorithm_not_allowed",
	signature: "attestation_invalid",
	malformed: "unknown",
	"user-verification": "user_verification_required",
	"sign-count": "unknown",
	"user-handle": "unknown",
	"backup-eligibility": "unknown",
	"no-challenge": "challenge_invalid",
	conflict: "credential_id_conflict",
	full: "credential_limit",
	unreadable: "invalid_request",
	revoked: "unauthorized",
};
const descriptionOf: Partial<Record<RegistrationRefusal, string>> = {
	conflict: "credential ID already registered",
	unreadable: "unreadable client data",
};

/** The routes that register a passkey from a session: creation options, then keeping what a response creates. */
export function registeringRoutes(p: RegisteringParts): {
	readonly options: Route;
	readonly verify: Route;
} {
	const audited = declaredAudit(p.audit, events);
	const options = p.exchange.post(
		"/oauth/webauthn/registration/options",
		async (_request, subject) => jsonAnswer(200, (await p.registrations.creation(subject)).options),
	);

	const verify = p.exchange.post(
		"/oauth/webauthn/registration/verify",
		async (request, subject) => {
			const { response, nickname } = request.json ?? {};
			if (typeof response !== "object" || response === null || Array.isArray(response)) {
				return invalid("response must be an object");
			}
			if (nickname !== undefined && (typeof nickname !== "string" || !isLabel(nickname)))
				return invalid("invalid nickname");
			// A revocation since the challenge was made, a reset's included, leaves nothing usable of it.
			const admitted = async (challengedAt: number) =>
				(await p.revocation.check(subject, challengedAt)) === "valid";
			const kept = await p.registrations.register(subject, response, nickname, admitted);
			if (kept.kind === "refused") {
				if (kept.reason === "revoked") return jsonAnswer(401, { error: errorOf.revoked });
				const description = descriptionOf[kept.reason];
				return jsonAnswer(400, {
					error: errorOf[kept.reason],
					...(description ? { error_description: description } : {}),
				});
			}
			const { credential } = kept;
			audited.record("passkey.registered", { subject, attributes: sourced(request) });
			return jsonAnswer(200, {
				credentialId: credential.id,
				...(credential.transports ? { transports: credential.transports } : {}),
				backedUp: credential.backedUp,
			});
		},
	);

	return { options, verify };
}
