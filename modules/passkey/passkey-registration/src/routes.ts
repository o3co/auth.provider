import { type Audit, declaredAudit } from "@mod/audit";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route, use } from "@mod/http";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { isLabel } from "@mod/labels";
import type { RegistrationRefusal, Registrations } from "@mod/passkeys";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import { determinedSource } from "@mod/request-source";
import type { Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import events from "./audit-events.ts";

export interface RouteParts {
	readonly sessions: Sessions;
	readonly registrations: Registrations;
	/** Whether the subject was revoked after a time: a passkey registered meanwhile is ended. */
	readonly revocation: Pick<SubjectRevocation, "check">;
	readonly window: Window;
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

const invalid = (description: string) =>
	jsonAnswer(400, { error: "invalid_request", error_description: description });

type Handler = (request: HttpRequest, subject: string) => Promise<HttpResponse>;

/** One of the subject's passkeys a body names, by `id`; none for another body. */
const idIn = (request: HttpRequest) => {
	const id = request.json?.id;
	return typeof id === "string" && id !== "" ? id : undefined;
};

/** The optional methods of `registrations` this package asks; a provider without one cannot tell. */
const asked = <T>(method: T | undefined): T => {
	if (method === undefined) throw new Unavailable("passkeys");
	return method;
};

export function registrationRoutes(p: RouteParts): {
	readonly options: Route;
	readonly verify: Route;
	readonly list: Route;
	readonly rename: Route;
	readonly remove: Route;
} {
	const audited = declaredAudit(p.audit, events);
	const sourced = (request: HttpRequest) => {
		const source = determinedSource(request);
		return source === undefined ? {} : { source };
	};
	/** Enters the session at `credentials`, then hands its subject on. */
	const entered = (handle: Handler) => async (request: HttpRequest) => {
		try {
			const entry = await p.sessions.enterFor(request, "credentials");
			if (entry.kind === "absent") return jsonAnswer(401, { error: "unauthorized" });
			if (entry.kind === "short") return jsonAnswer(403, entry.answer);
			return await handle(request, entry.session.context.subject);
		} catch (error) {
			if (isUnavailable(error)) return jsonAnswer(503, { error: "temporarily_unavailable" });
			throw error;
		}
	};
	const post = (path: string, handle: Handler): Route => ({
		method: "POST",
		path,
		uses: [
			use(csrfChecked),
			use(requestsPerSource, { name: "passkey-registration", window: p.window }),
		],
		takes: ["json", "none"],
		handle: entered(handle),
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
		const { credential } = kept;
		// A revocation since the challenge was made, a reset's included, ends what it wrote: it is undone.
		if (
			kept.challengedAt !== undefined &&
			(await p.revocation.check(subject, kept.challengedAt)) === "revoked"
		) {
			await asked(p.registrations.removed)(subject, credential.id);
			return jsonAnswer(401, { error: "unauthorized" });
		}
		audited.record("passkey.registered", { subject, attributes: sourced(request) });
		return jsonAnswer(200, {
			credentialId: credential.id,
			...(credential.transports ? { transports: credential.transports } : {}),
			backedUp: credential.backedUp,
		});
	});

	const list: Route = {
		method: "GET",
		changesState: false,
		path: "/oauth/webauthn/registrations",
		handle: entered(async (_request, subject) => {
			const listed = await asked(p.registrations.listed)(subject);
			return jsonAnswer(200, {
				passkeys: listed.map((passkey) => ({
					credentialId: passkey.id,
					...(passkey.nickname ? { nickname: passkey.nickname } : {}),
					...(passkey.transports ? { transports: passkey.transports } : {}),
					backupEligible: passkey.backupEligible,
					backedUp: passkey.backedUp,
					...(passkey.at === undefined ? {} : { createdAt: passkey.at }),
				})),
			});
		}),
	};

	const rename = post("/oauth/webauthn/registrations/rename", async (request, subject) => {
		const id = idIn(request);
		const { nickname } = request.json ?? {};
		if (id === undefined) return invalid("id must be a credential id");
		if (typeof nickname !== "string" || !isLabel(nickname)) return invalid("invalid nickname");
		if ((await asked(p.registrations.renamed)(subject, id, nickname)) === "unknown") {
			return jsonAnswer(404, { error: "not_found" });
		}
		audited.record("passkey.renamed", { subject, attributes: sourced(request) });
		return jsonAnswer(200, {});
	});

	const remove = post("/oauth/webauthn/registrations/remove", async (request, subject) => {
		const id = idIn(request);
		if (id === undefined) return invalid("id must be a credential id");
		const removed = await asked(p.registrations.removed)(subject, id);
		if (!removed.removed) return jsonAnswer(404, { error: "not_found" });
		audited.record("passkey.removed", { subject, attributes: sourced(request) });
		return jsonAnswer(200, { last: removed.empty });
	});

	return { options, verify, list, rename, remove };
}
