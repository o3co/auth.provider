import type { Audit } from "@mod/audit";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { isUnavailable, type Log } from "@mod/kernel";
import type { LoginGate, Logins } from "@mod/login-gates";
import type { Factors } from "@mod/mfa";
import type { LockoutPolicy, Lockouts } from "@mod/rate-limit";
import type { Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import type { Permits } from "../permits/permits.ts";
import { auditedBy } from "../recording/recording.ts";
import {
	field,
	type Handler,
	loginRequired,
	postedTransaction,
	proofOf,
	revokedSince,
	unavailable,
	unknownTransaction,
} from "../routing.ts";
import { lockoutName } from "../section.ts";
import type { Transaction } from "../transactions/records.ts";
import { askedFrom, type Transactions } from "../transactions/transactions.ts";

/** What a proof that passed adds to the amr. */
type Proved = { readonly amr: readonly string[] };

export interface GateParts {
	readonly factors: Pick<Factors, "asks">;
	readonly transactions: Transactions;
}

/** The login gate: holds a login whose subject must prove a factor or bind a first one. */
export function gateOver(p: GateParts): LoginGate["hold"] {
	return async (_request, facts, done, from) => {
		const asks = await p.factors.asks(facts.subject);
		if (asks === "nothing") return { kind: "pass" as const };
		const enroll = asks === "binding";
		const started = await p.transactions.start({
			subject: facts.subject,
			purpose: enroll ? "enroll-login" : "login",
			facts,
			...(done === undefined ? {} : { done }),
			...(from === undefined ? {} : { from }),
		});
		const error = enroll ? "mfa_enrollment_required" : "mfa_required";
		return {
			kind: "held" as const,
			answer: { error, transaction: started.id, expires_in: started.expiresIn },
			cookies: started.cookies,
		};
	};
}

export interface ResumeParts {
	readonly sessions: Pick<Sessions, "close">;
	readonly logins: Pick<Logins, "resume">;
	readonly revocation: Pick<SubjectRevocation, "check">;
	readonly transactions: Transactions;
	readonly log: Pick<Log, "warn">;
}

/** What makes, once a resumed login opens, what it adds to its answer; a body never holds `status`. */
type Carried = () => Promise<object | HttpResponse>;
const isResponse = (made: object): made is HttpResponse => "status" in made;

/**
 * Goes on with a held login after the gate `mfa`, adding `proved` to its amr; answers what it held,
 * with what `carried` makes once it opens, and only then: a response it makes instead closes the
 * session and is answered, and a throw closes it as best it can and goes on, an unavailable part
 * answering `503` as a response.
 */
export function resumeOver(p: ResumeParts) {
	/** What carried makes once the session opened; a response it makes closes the session. */
	const madeIn = async (handle: string, carried: Carried): Promise<object | HttpResponse> => {
		let made: object | HttpResponse;
		try {
			made = await carried();
		} catch (error) {
			await p.sessions.close(handle).catch(() => undefined);
			// Answered as a response, so the transaction's cookie is cleared too.
			if (isUnavailable(error)) return unavailable;
			throw error;
		}
		if (!isResponse(made)) return made;
		try {
			await p.sessions.close(handle);
		} catch (error) {
			if (isUnavailable(error)) return unavailable;
			throw error;
		}
		return made;
	};
	return async (
		request: HttpRequest,
		t: Transaction & { readonly purpose: "login" | "enroll-login" },
		proved: readonly string[],
		carried?: Carried,
		opened?: (handle: string) => Promise<void>,
	) => {
		const facts = t.facts ?? { subject: t.subject, amr: [] };
		const amr = [...new Set([...facts.amr, ...proved])];
		// Held with no time, it is unknown: never the opening's.
		const authenticatedAt = facts.authenticatedAt ?? "unknown";
		const resuming = { ...facts, amr, authenticatedAt };
		const resumed = await p.logins.resume(request, resuming, "mfa", t.done, t.from);
		if (resumed.kind === "held")
			return jsonAnswer(403, resumed.answer, { cookies: resumed.cookies });
		// Any other outcome opened nothing (a resume past its caller's deadline): refused as a gate would.
		if (resumed.kind !== "opened") {
			p.log.warn("mfa-flows.login_expired", {});
			return jsonAnswer(403, { error: "login_required" });
		}
		// A revocation landing between the proof and the opening ends the session before its cookie goes out.
		if (await revokedSince(p.revocation, t)) {
			await p.sessions.close(resumed.session.id);
			return { ...loginRequired, cookies: [p.transactions.cleared()] };
		}
		await opened?.(resumed.session.id);
		const made = carried === undefined ? undefined : await madeIn(resumed.session.id, carried);
		// Its cookie never goes out: the session closed, or failing to, is no one's.
		if (made !== undefined && isResponse(made)) {
			return { ...made, cookies: [...(made.cookies ?? []), p.transactions.cleared()] };
		}
		const cookies = [...resumed.cookies, p.transactions.cleared()];
		const done = made ? { ...(t.done as object | undefined), ...made } : (t.done ?? {});
		return jsonAnswer(200, done, { cookies });
	};
}

export interface ProofParts extends ResumeParts {
	readonly factors: Pick<Factors, "guessable" | "held" | "challenge" | "prove">;
	readonly sessions: Pick<Sessions, "enter" | "raise" | "close">;
	readonly lockouts: Pick<Lockouts, "reserve" | "succeeded" | "abandoned">;
	readonly policy: LockoutPolicy;
	readonly permits: Pick<Permits, "grant">;
	readonly audit: Pick<Audit, "record">;
	/** Answers the challenge route in an enrollment's transaction. */
	readonly enrollmentChallenge: (
		request: HttpRequest,
		id: string,
		t: Transaction,
	) => Promise<HttpResponse>;
}

/** A transaction a factor is proved in: a login's or a step-up's. */
const proved = (t: Transaction): t is Transaction & { readonly purpose: "login" | "step-up" } =>
	t.purpose === "login" || t.purpose === "step-up";
/** The challenge route also takes an enrollment's transaction. */
const anyPurpose = (_: Transaction): _ is Transaction => true;

const unknownFactor = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "unknown factor",
});

export function proofOver(p: ProofParts) {
	const audited = auditedBy(p.audit);
	const resumeLogin = resumeOver(p);

	/** The transaction a POST names, of a purpose the route takes, or the answer refusing it. */
	const proving = async <T extends Transaction>(
		request: HttpRequest,
		takes: (t: Transaction) => t is T,
	) => {
		const id = postedTransaction(request);
		if (!id) return unknownTransaction;
		const found = await p.transactions.find(request, id);
		if (!found) return unknownTransaction;
		if (!takes(found.transaction)) return unknownTransaction;
		// Widened, so the step-up check below narrows on the purpose; the caller gets it as T.
		const t: Transaction = found.transaction;
		// A step-up raises only the session that started it.
		if (t.purpose === "step-up" && (await p.sessions.enter(request))?.id !== t.handle) {
			return unknownTransaction;
		}
		if (await revokedSince(p.revocation, t)) {
			await p.transactions.take(id);
			return loginRequired;
		}
		return { id, t: found.transaction };
	};

	const challenge: Handler = async (request) => {
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

	const verify: Handler = async (request) => {
		const named = await proving(request, proved);
		if ("status" in named) return named;
		const { id: txId, t } = named;
		const factor = field(request, "factor_id") ?? "";
		const guessable = await p.factors.guessable(t.subject, factor);
		if (guessable === undefined) return unknownFactor;
		// Both the lockout and the transaction are spent before the guess is judged, so racing
		// guesses cannot pass either limit.
		const reserved = guessable
			? await p.lockouts.reserve(lockoutName, t.subject, p.policy)
			: undefined;
		const judging = { purpose: t.purpose, factor };
		if (reserved?.kind === "held") {
			audited("locked", t.subject, request, { ...judging, hold: reserved.hold });
			const retry =
				reserved.retryAfterMs === undefined
					? {}
					: { "retry-after": String(Math.ceil(reserved.retryAfterMs / 1000)) };
			return jsonAnswer(429, { error: "mfa_locked", hold: reserved.hold }, { headers: retry });
		}
		// The reservation is settled once a wrong guess keeps it or `succeeded` hands it back;
		// anything else, a throw included, hands it back below.
		let settled = false;
		const verifying = async (): Promise<HttpResponse | Proved> => {
			const spent = await p.transactions.spend(txId);
			if (spent === undefined) return unknownTransaction;
			const { left, challenge } = spent;
			const kept = challenge?.factor === factor ? challenge.sealed : undefined;
			const proof = proofOf(request) ?? "";
			const result = await p.transactions.judged(txId, () =>
				p.factors.prove(t.subject, factor, proof, kept),
			);
			if (result.kind !== "valid") {
				// A replayed or raced proof was right once: it is no guess.
				settled = result.kind === "invalid";
				audited("verify.failure", t.subject, request, { ...judging, reason: result.kind });
				// Only a wrong guess keeps its reservation, so only it starts the hold it would.
				if (settled && reserved?.holds) {
					audited("locked.first", t.subject, request, { ...judging, hold: reserved.holds });
				}
				if (left === 0) await p.transactions.take(txId);
				return jsonAnswer(401, { error: "mfa_invalid", attempts_remaining: left });
			}
			// Taken once: of two proofs racing on one transaction, only one goes on.
			if (!(await p.transactions.take(txId))) return unknownTransaction;
			// A factor guessing cannot beat ends the run too, though it reserved nothing; the budget stays.
			await p.lockouts.succeeded(lockoutName, t.subject, p.policy, reserved?.reservation);
			settled = true;
			audited("verified", t.subject, request, judging);
			return { amr: result.amr };
		};
		const outcome = await verifying().finally(async () => {
			if (reserved && !settled) {
				await p.lockouts.abandoned(lockoutName, t.subject, p.policy, reserved.reservation);
			}
		});
		if ("status" in outcome) return outcome;
		// A local proof of a factor guessing cannot beat lets this session release its lockout.
		const granting = guessable ? undefined : grant;
		return t.purpose === "step-up"
			? raiseSession(request, outcome.amr, granting)
			: resumeLogin(request, t, outcome.amr, undefined, granting);
	};

	/** Grants the session a release; one that cannot be written leaves the login as it is, with none. */
	const grant = async (handle: string) => {
		try {
			await p.permits.grant(handle);
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			p.log.warn("mfa-flows.release_permit_unrecorded", {});
		}
	};

	/** A step-up's success: raises the session under a new cookie. */
	const raiseSession = async (
		request: HttpRequest,
		amr: readonly string[],
		raisedAs?: (handle: string) => Promise<void>,
	) => {
		const raised = await p.sessions.raise(request, amr);
		if (!raised) return loginRequired;
		if (!raised.raised)
			return jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies: raised.cookies });
		await raisedAs?.(raised.session.id);
		const cookies = [...raised.cookies, p.transactions.cleared()];
		return jsonAnswer(200, { step_up: "verified" }, { cookies });
	};

	const transaction: Handler = async (request) => {
		const txId = request.headers.get("mfa-transaction");
		const found = await p.transactions.find(request, txId);
		if (!found) return unknownTransaction;
		if (await revokedSince(p.revocation, found.transaction)) return loginRequired;
		return jsonAnswer(200, {
			purpose: found.transaction.purpose,
			factors: await p.factors.held(found.transaction.subject),
			attempts_remaining: found.transaction.attemptsLeft,
			expires_in: Math.floor(found.leftMs / 1000),
		});
	};

	const stepUp: Handler = async (request) => {
		const session = await p.sessions.enter(request);
		if (!session) return loginRequired;
		if ((await p.factors.held(session.context.subject)).length === 0) {
			return jsonAnswer(403, { error: "mfa_no_qualifying_factor" });
		}
		const started = await p.transactions.start({
			subject: session.context.subject,
			handle: session.id,
			purpose: "step-up",
		});
		return jsonAnswer(
			200,
			{ transaction: started.id, expires_in: started.expiresIn },
			{ cookies: started.cookies },
		);
	};

	return { challenge, verify, transaction, stepUp };
}
