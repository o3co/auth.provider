import { createHash } from "node:crypto";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { isUnavailable, type Log } from "@mod/kernel";
import { loginSource } from "@mod/login-attributes";
import type { Logins } from "@mod/login-gates";
import type { LockoutPolicy, Lockouts } from "@mod/rate-limit";
import { acceptedAttributes, type User, type Users } from "@mod/users";

/** The name an identifier's attempts are kept under. */
const accountAttempts = "login-password.account";

/**
 * An identifier's key: folded wider than users matches, so spellings a ledger may take alike share
 * one count, and hashed, so no identifier is kept.
 */
const accountKey = (identifier: string) =>
	createHash("sha256").update(identifier.normalize("NFKC").toLowerCase()).digest("base64url");

/** A JSON answer that is never cached, setting the cookies given. */
export const answer = (status: number, json: unknown, cookies?: readonly string[]): HttpResponse =>
	jsonAnswer(status, json, cookies ? { cookies } : {});

/** What a password login proves. */
export const proves: readonly string[] = ["pwd"];

/** The user's attributes as users accepts them, as session keeps them; session applies the caps. */
const attributesOf = (user: User) => ({
	source: loginSource.users,
	values: acceptedAttributes(user.attributes),
});

/** The login handler: a password checked, counted per identifier, and the login passed to the gates. */
export function loginWith(parts: {
	readonly known: Users;
	readonly gates: Logins;
	readonly budgets: Lockouts;
	readonly policy: LockoutPolicy;
	readonly windowMs: number;
	readonly recordLogin: (
		request: HttpRequest,
		outcome: "succeeded" | "held" | "failed",
		subject?: string,
	) => void;
	readonly log: Log;
	/** `kernel`'s clock, read once before the password is verified: when the login's proof began. */
	readonly now: () => number;
}) {
	const { known, gates, budgets, policy, windowMs, recordLogin, log, now } = parts;
	return async (request: HttpRequest): Promise<HttpResponse> => {
		if (request.fields.repeated().length > 0) {
			return answer(400, { error: "repeated_parameter" });
		}
		const field = (name: string) => request.fields.single(name);
		const destination = field("redirect_to");
		// A JSON destination that is not a string is refused; null is none.
		const mistyped = request.mistyped?.has("redirect_to") && request.json?.redirect_to !== null;
		if (mistyped) return answer(400, { error: "invalid_redirect" });
		if (destination !== undefined && !gates.returnAllowed(destination)) {
			return answer(400, { error: "invalid_redirect" });
		}
		const username = field("username");
		const password = field("password");
		if (!username || !password) return answer(400, { error: "invalid_request" });
		const key = accountKey(username);
		const reserved = await budgets.reserve(accountAttempts, key, policy).catch((error) => {
			if (isUnavailable(error)) return undefined;
			throw error;
		});
		if (!reserved) return answer(503, { error: "service_unavailable" });
		if (reserved.kind === "held") {
			const seconds = Math.max(1, Math.ceil((reserved.retryAfterMs ?? windowMs) / 1000));
			return jsonAnswer(
				429,
				{ error: "too_many_attempts" },
				{ headers: { "retry-after": String(seconds) } },
			);
		}
		const provenSince = now();
		const verified = await known.verify(username, password).catch(async (error) => {
			// A guess never judged is handed back; the run goes on without it.
			if (isUnavailable(error))
				await budgets.abandoned(accountAttempts, key, policy, reserved.reservation);
			throw error;
		});
		if (verified.kind !== "user") {
			recordLogin(request, "failed");
			return answer(401, { error: "invalid_credentials" });
		}
		// A gate that holds the login answers this once it lets the login through.
		const done = destination === undefined ? {} : { redirect_to: destination };
		const facts = {
			subject: verified.user.subject,
			amr: proves,
			// Authenticated here, so as fresh as the session it opens, however long a gate holds it first.
			authenticatedAt: "opening" as const,
			attributes: attributesOf(verified.user),
			// session compares it with the subject's boundary, however late the ledger answered.
			provenSince,
		};
		const outcome = await gates.login(request, facts, done).catch(async (error) => {
			// A gate that cannot tell judged nothing either: the guess is handed back.
			if (isUnavailable(error))
				await budgets.abandoned(accountAttempts, key, policy, reserved.reservation);
			throw error;
		});
		// A login a gate refused, or session revoked, fails as a wrong password does, in its answer and its count alike.
		if (outcome.kind === "refused" || outcome.kind === "revoked") {
			recordLogin(request, "failed");
			return answer(401, { error: "invalid_credentials" });
		}
		// The login is open or held already: a run that cannot be ended stays counted, the safe side, and the login is answered.
		await budgets.succeeded(accountAttempts, key, policy, reserved.reservation).catch((error) => {
			if (!isUnavailable(error)) throw error;
			log.warn("login-password.run_unended", {});
		});
		if (outcome.kind === "held") {
			recordLogin(request, "held", facts.subject);
			return answer(403, outcome.answer, outcome.cookies);
		}
		recordLogin(request, "succeeded", facts.subject);
		return answer(200, done, outcome.cookies);
	};
}
