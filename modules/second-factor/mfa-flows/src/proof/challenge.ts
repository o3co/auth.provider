import { jsonAnswer } from "@mod/http";
import type { auditedBy } from "../recording/recording.ts";
import { field, type Handler, unknownTransaction } from "../requests/requests.ts";
import { askedFrom } from "../transactions/transactions.ts";
import type { ProofParts } from "./proof.ts";
import { anyPurpose, type Proving, unknownFactor } from "./proving.ts";

/** A factor's challenge asked in a transaction, or an enrollment's challenge where it is one's. */
export function challengeWith(
	p: ProofParts,
	proving: Proving,
	audited: ReturnType<typeof auditedBy>,
): Handler {
	return async (request) => {
		const named = await proving(request, anyPurpose);
		if ("status" in named) return named;
		const { id, t } = named;
		if (t.purpose === "enroll" || t.purpose === "enroll-login")
			return p.enrollmentChallenge(request, id, t);
		const factor = field(request, "factor_id") ?? "";
		const asked = await p.factors
			.challenge(t.subject, factor, t.deadline, askedFrom(t))
			.catch(async (error) => {
				// Asking voids the challenge before, even when this one cannot be sent.
				await p.transactions.challenged(id);
				throw error;
			});
		if (asked.kind === "unknown") return unknownFactor;
		const sent = asked.kind === "sent" ? { factor, sealed: asked.sealed } : undefined;
		if (!(await p.transactions.challenged(id, sent))) return unknownTransaction;
		if (asked.kind === "limited") return jsonAnswer(429, { error: "rate_limited" });
		if (asked.kind === "refused") {
			const refused = { kind: asked.factorKind, purpose: t.purpose };
			if (asked.reason === "contact-changed")
				audited("email_address_mismatch", t.subject, request, refused);
			return jsonAnswer(403, { error: "mfa_factor_refused" });
		}
		if (asked.kind === "none") return jsonAnswer(200, {});
		const sentOf = { kind: asked.factorKind, purpose: t.purpose };
		audited("challenge.sent", t.subject, request, sentOf);
		return jsonAnswer(200, asked.show);
	};
}
