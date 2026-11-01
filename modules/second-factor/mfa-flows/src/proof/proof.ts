import type { Audit } from "@mod/audit";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { isUnavailable, type Log } from "@mod/kernel";
import type { LoginGate, Logins } from "@mod/login-gates";
import { secondFactorAmr } from "@mod/mfa-extensions";
import type { FactorReading } from "@mod/mfa-reading";
import type { LockoutPolicy, Lockouts } from "@mod/rate-limit";
import type { Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import type { Permits } from "../permits/permits.ts";
import { auditedBy } from "../recording/recording.ts";
import { loginRequired, revokedSince, unavailable } from "../requests/requests.ts";
import type { Transaction } from "../transactions/records.ts";
import type { Transactions } from "../transactions/transactions.ts";
import { challengeWith } from "./challenge.ts";
import { provingWith } from "./proving.ts";
import { stepUpWith, transactionWith } from "./transaction.ts";
import { verifyWith } from "./verify.ts";

/** What a proof that passed adds to the amr. */
export interface GateParts {
	readonly factors: Pick<FactorReading, "asks">;
	readonly transactions: Transactions;
}

/** The login gate: holds a login whose subject must prove a factor or bind a first one, unless its amr holds one proved. */
export function gateOver(p: GateParts): LoginGate["hold"] {
	return async (_request, facts, done, from) => {
		if (facts.amr.includes(secondFactorAmr)) return { kind: "pass" as const };
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

/** What a resumed login's maker makes once it opens: the answer instead, or what it adds to `done`. */
type Made = { readonly answer: HttpResponse } | { readonly adds: object };
type Carried = () => Promise<Made>;

/**
 * Goes on with a held login after the gate `mfa`, adding `proved` to its amr; answers what it held,
 * with what `carried` makes once it opens, and only then: an answer it makes instead closes the
 * session and is answered, and a throw closes it as best it can and goes on, an unavailable part
 * answering `503` as an answer.
 */
export function resumeOver(p: ResumeParts) {
	/** What carried makes once the session opened; an answer it makes closes the session. */
	const madeIn = async (handle: string, carried: Carried): Promise<Made> => {
		let made: Made;
		try {
			made = await carried();
		} catch (error) {
			await p.sessions.close(handle).catch(() => undefined);
			// Answered as an answer, so the transaction's cookie is cleared too.
			if (isUnavailable(error)) return { answer: unavailable };
			throw error;
		}
		if (!("answer" in made)) return made;
		try {
			await p.sessions.close(handle);
		} catch (error) {
			if (isUnavailable(error)) return { answer: unavailable };
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
		// A gate refused it, or session did by the held facts' `provenSince`: the transaction is taken, its cookie goes.
		if (resumed.kind === "refused" || resumed.kind === "revoked") {
			return jsonAnswer(403, { error: "login_required" }, { cookies: [p.transactions.cleared()] });
		}
		// Any other outcome opened nothing (a resume past its caller's deadline): refused as a gate would.
		if (resumed.kind !== "opened") {
			p.log.warn("mfa-flows.login_expired", {});
			// Answered as a refusal is, cookie and all: only the log tells them apart.
			return jsonAnswer(403, { error: "login_required" }, { cookies: [p.transactions.cleared()] });
		}
		// A revocation landing between the proof and the opening ends the session before its cookie goes out.
		if (await revokedSince(p.revocation, t)) {
			await p.sessions.close(resumed.session.id);
			return { ...loginRequired, cookies: [p.transactions.cleared()] };
		}
		await opened?.(resumed.session.id);
		const made = carried === undefined ? undefined : await madeIn(resumed.session.id, carried);
		// Its cookie never goes out: the session closed, or failing to, is no one's.
		if (made !== undefined && "answer" in made) {
			const { answer } = made;
			return { ...answer, cookies: [...(answer.cookies ?? []), p.transactions.cleared()] };
		}
		const cookies = [...resumed.cookies, p.transactions.cleared()];
		const done = made ? { ...(t.done as object | undefined), ...made.adds } : (t.done ?? {});
		return jsonAnswer(200, done, { cookies });
	};
}

export interface ProofParts extends ResumeParts {
	readonly factors: Pick<FactorReading, "guessable" | "held" | "challenge" | "prove">;
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

export function proofOver(p: ProofParts) {
	const audited = auditedBy(p.audit);
	const proving = provingWith(p);
	return {
		challenge: challengeWith(p, proving, audited),
		verify: verifyWith(p, proving, audited, resumeOver(p)),
		transaction: transactionWith(p),
		stepUp: stepUpWith(p),
	};
}
