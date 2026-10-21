import { type Audit, declaredAudit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route, use } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import { isLabel } from "@mod/labels";
import type { RegistrationRefusal, Registrations } from "@mod/passkeys";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import { determinedSource } from "@mod/request-source";
import type { Sessions } from "@mod/session";
import events from "./audit-events.ts";

export interface RouteParts {
	readonly sessions: Sessions;
	readonly registrations: Registrations;
	readonly window: Window;
	readonly audit: Audit;
}

/** Each refusal in the words clients of these routes know. */
const errorOf: Record<RegistrationRefusal, string> = {
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
};
const descriptionOf: Partial<Record<RegistrationRefusal, string>> = {
	conflict: "credential ID already registered",
	unreadable: "unreadable client data",
};

const invalid = (description: string) =>
	jsonAnswer(400, { error: "invalid_request", error_description: description });

export function registrationRoutes(p: RouteParts): {
	readonly options: Route;
	readonly verify: Route;
} {
	const post = (
		path: string,
		handle: (request: HttpRequest, subject: string) => Promise<HttpResponse>,
	): Route => ({
		method: "POST",
		path,
		uses: [
			use(csrfChecked),
			use(requestsPerSource, { name: "passkey-registration", window: p.window }),
		],
		takes: ["json", "none"],
		handle: async (request) => {
			try {
				const entry = await p.sessions.enterFor(request, "credentials");
				if (entry.kind === "absent") return jsonAnswer(401, { error: "unauthorized" });
				if (entry.kind === "short") return jsonAnswer(403, entry.answer);
				return await handle(request, entry.session.context.subject);
			} catch (error) {
				if (isUnavailable(error)) return jsonAnswer(503, { error: "temporarily_unavailable" });
				throw error;
			}
		},
	});

	const options = post("/oauth/webauthn/registration/options", async (_request, subject) =>
		jsonAnswer(200, (await p.registrations.creation(subject)).options),
	);

	const verify = post("/oauth/webauthn/registration/verify", async (request, subject) => {
		const { response, nickname } = request.json ?? {};
		if (typeof response !== "object" || response === null || Array.isArray(response)) {
			return invalid("response must be an object");
		}
		if (nickname !== undefined && (typeof nickname !== "string" || !isLabel(nickname)))
			return invalid("invalid nickname");
		const kept = await p.registrations.register(subject, response, nickname);
		if (kept.kind === "refused") {
			const description = descriptionOf[kept.reason];
			return jsonAnswer(400, {
				error: errorOf[kept.reason],
				...(description ? { error_description: description } : {}),
			});
		}
		const source = determinedSource(request);
		declaredAudit(p.audit, events).record("passkey.registered", {
			subject,
			attributes: source === undefined ? {} : { source },
		});
		const { credential } = kept;
		return jsonAnswer(200, {
			credentialId: credential.id,
			...(credential.transports ? { transports: credential.transports } : {}),
			backedUp: credential.backedUp,
		});
	});

	return { options, verify };
}
