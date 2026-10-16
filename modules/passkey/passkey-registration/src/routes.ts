import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, noStore, type Route, use } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import type { Sessions } from "@mod/session";
import type { RegistrationRefusal, Registrations } from "@mod/webauthn";

export interface RouteParts {
	readonly sessions: Sessions;
	readonly registrations: Registrations;
	readonly window: Window;
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

const answer = (status: number, json: unknown): HttpResponse => ({
	status,
	headers: noStore,
	body: { json },
});
const invalid = (description: string) =>
	answer(400, { error: "invalid_request", error_description: description });

/** A nickname is 1 to 64 UTF-16 code units. */
const isNickname = (value: unknown): value is string =>
	typeof value === "string" && value.length >= 1 && value.length <= 64;

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
				if (entry.kind === "absent") return answer(401, { error: "unauthorized" });
				if (entry.kind === "short") return answer(403, entry.answer);
				return await handle(request, entry.session.context.subject);
			} catch (error) {
				if (isUnavailable(error)) return answer(503, { error: "temporarily_unavailable" });
				throw error;
			}
		},
	});

	const options = post("/oauth/webauthn/registration/options", async (_request, subject) =>
		answer(200, (await p.registrations.creation(subject)).options),
	);

	const verify = post("/oauth/webauthn/registration/verify", async (request, subject) => {
		const { response, nickname } = request.json ?? {};
		if (typeof response !== "object" || response === null || Array.isArray(response)) {
			return invalid("response must be an object");
		}
		if (nickname !== undefined && !isNickname(nickname)) return invalid("invalid nickname");
		const kept = await p.registrations.register(subject, response, nickname);
		if (kept.kind === "refused") {
			const description = descriptionOf[kept.reason];
			return answer(400, {
				error: errorOf[kept.reason],
				...(description ? { error_description: description } : {}),
			});
		}
		const { credential } = kept;
		return answer(200, {
			credentialId: credential.id,
			...(credential.transports ? { transports: credential.transports } : {}),
			backedUp: credential.backedUp,
		});
	});

	return { options, verify };
}
