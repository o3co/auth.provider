import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { refusedEntry, type Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import type { Transaction } from "./transactions/records.ts";

/** What each internal module gives the package for one route. */
export type Handler = (request: HttpRequest) => Promise<HttpResponse>;

/** One answer for every transaction that cannot be used, so it tells nothing about why. */
export const unknownTransaction = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "unknown or expired transaction",
});
export const loginRequired = jsonAnswer(401, { error: "login_required" });
export const unavailable = jsonAnswer(503, { error: "temporarily_unavailable" });
export const invalidLabel = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "invalid label",
});

/** A single value from the body; the query is never read, so nothing secret goes in a URL. */
export const field = (request: HttpRequest, name: string) => request.fields.single(name);
/** The proof a POST sends: a string as it is, a JSON object as its JSON text (a WebAuthn response, say); anything else is none. */
export const proofOf = (request: HttpRequest) => {
	const sent = request.json?.proof;
	const object = typeof sent === "object" && sent !== null && !Array.isArray(sent);
	return object ? JSON.stringify(sent) : field(request, "proof");
};
/** The transaction a POST names in its body or its header; none when neither names one, false when the two differ. */
export const postedTransaction = (request: HttpRequest): string | false | undefined => {
	const body = field(request, "transaction_id") || undefined;
	const header = request.headers.get("mfa-transaction");
	return body && header && body !== header ? false : (body ?? header);
};

/** Whether the subject was revoked after the transaction started. */
export const revokedSince = async (revocation: Pick<SubjectRevocation, "check">, t: Transaction) =>
	(await revocation.check(t.subject, t.startedAt)) === "revoked";

/** The session's entry for changing credentials, or the answer refusing it. */
export const managing = async (sessions: Sessions, request: HttpRequest) => {
	const entry = await sessions.enterFor(request, "credentials");
	return entry.kind === "entered" ? entry.session : refusedEntry(entry);
};
