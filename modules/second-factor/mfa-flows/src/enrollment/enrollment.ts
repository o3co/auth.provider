import type { Audit } from "@mod/audit";
import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { type Factors, isLabel } from "@mod/mfa";
import type { BindingProofs } from "@mod/mfa-binding-proof";
import type { AskedFrom } from "@mod/mfa-extensions";
import type { Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import { auditedBy } from "../recording/recording.ts";
import {
	field,
	type Handler,
	invalidLabel,
	loginRequired,
	managing,
	postedTransaction,
	proofOf,
	revokedSince,
	unknownTransaction,
} from "../routing.ts";
import type { BindingChallenge, Transaction } from "../transactions/records.ts";
import { askedFrom, type Transactions } from "../transactions/transactions.ts";

const unknownKind = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "unknown kind",
});
/** The kinds of `mfa`'s answer to a call, but the one named. */
type Refused<T extends (...args: never[]) => Promise<{ readonly kind: string }>, Done> = Exclude<
	Awaited<ReturnType<T>>["kind"],
	Done
>;
type Refusal = Refused<Factors["begin"], "begun"> | Refused<Factors["bind"], "bound">;
/** What `mfa` refuses a binding with, as answered here; anything else refuses it too. */
const refusals: Readonly<Partial<Record<Refusal, HttpResponse>>> = {
	full: jsonAnswer(409, { error: "mfa_factor_limit" }),
	duplicate: jsonAnswer(409, { error: "mfa_factor_duplicate" }),
	limited: jsonAnswer(429, { error: "rate_limited" }),
	refused: jsonAnswer(403, { error: "mfa_factor_refused" }),
	"binding-proof-required": jsonAnswer(403, { error: "mfa_binding_proof_required" }),
};
const enrollmentConflict = jsonAnswer(409, { error: "mfa_enrollment_conflict" });

export interface EnrollmentParts {
	readonly factors: Factors;
	readonly bindingProof: BindingProofs;
	readonly sessions: Sessions;
	readonly revocation: SubjectRevocation;
	readonly transactions: Transactions;
	readonly audit: Pick<Audit, "record">;
	/** Goes on with a login held for its first factor, adding `proved` to its amr and `carried` to its answer. */
	readonly resume: (
		request: HttpRequest,
		t: Transaction & { readonly purpose: "login" | "enroll-login" },
		proved: readonly string[],
		carried: object,
	) => Promise<HttpResponse>;
}

/** The transaction an enrollment goes on in, and how far its binding proof went. */
interface Open
	extends Pick<Transaction, "purpose" | "deadline" | "bindingChallenge" | "bindingPassed"> {
	readonly id: string;
	readonly expiresIn: number;
}

/** Whose binding begins, and where: its transaction, or the session whose own starts once it holds something. */
interface Enrolling {
	readonly subject: string;
	readonly where: Open | { readonly session: string };
	/** Whom `mfa` is asked for: the session, or the transaction's login or session. */
	readonly from: AskedFrom;
}

export function enrollmentOver(p: EnrollmentParts) {
	const audited = auditedBy(p.audit);
	/** A session's enrollment goes on only in that session, entered as it began; the answer refusing it, or nothing. */
	const outsideSession = async (request: HttpRequest, t: Transaction) => {
		if (t.purpose !== "enroll") return undefined;
		const session = await managing(p.sessions, request);
		if ("status" in session) return session;
		return session.id === t.handle ? undefined : loginRequired;
	};

	/** Whose binding begins, and where; or the answer refusing it. A session's enrollment writes nothing yet. */
	const enrolling = async (
		request: HttpRequest,
		txId: string | undefined,
	): Promise<HttpResponse | Enrolling> => {
		if (!txId) {
			const session = await managing(p.sessions, request);
			if ("status" in session) return session;
			const from: AskedFrom = { kind: "session", handle: session.id };
			return { subject: session.context.subject, where: { session: session.id }, from };
		}
		const found = await p.transactions.find(request, txId);
		if (!found) return unknownTransaction;
		const t = found.transaction;
		if (t.purpose !== "enroll-login" && t.purpose !== "enroll") return unknownTransaction;
		if (await revokedSince(p.revocation, t)) {
			await p.transactions.take(txId);
			return loginRequired;
		}
		const elsewhere = await outsideSession(request, t);
		if (elsewhere) return elsewhere;
		const expiresIn = Math.floor(found.leftMs / 1000);
		return { subject: t.subject, where: { ...t, id: txId, expiresIn }, from: askedFrom(t) };
	};

	/** Holds what the enrollment keeps, in its transaction or one started in the session: where, or none when no longer in use. */
	const keep = async (
		e: Enrolling,
		held: { readonly pending: string } | { readonly bindingChallenge: BindingChallenge },
	) => {
		const { where } = e;
		if ("session" in where) {
			const subject = e.subject;
			return p.transactions.start({ subject, purpose: "enroll", handle: where.session, ...held });
		}
		const kept =
			"pending" in held
				? await p.transactions.hold(where.id, held.pending)
				: await p.transactions.bindingSent(where.id, held.bindingChallenge);
		return kept ? { id: where.id, expiresIn: where.expiresIn, cookies: [] } : undefined;
	};

	/** Asks mfa-binding-proof to send the binding proof, good until `until`: what it sent, nothing when none is asked, or the answer refusing it. */
	const sendBinding = async (subject: string, until: number, from: AskedFrom) => {
		const sent = await p.bindingProof.challenge(subject, until, from);
		if (sent.kind === "none") return undefined;
		if (sent.kind === "limited") return jsonAnswer(429, { error: "rate_limited" });
		if (sent.kind === "refused") return jsonAnswer(403, { error: "mfa_binding_proof_unavailable" });
		const challenge = { proof: sent.proof, sealed: sent.sealed };
		return { shown: { ...sent.show, proof: sent.proof }, challenge };
	};

	/** Judges a proof sent for the binding challenge held: the pass, for this transaction and kind alone, or the answer refusing it. */
	const proveSent = async (
		request: HttpRequest,
		{
			subject,
			kind,
			open,
		}: { readonly subject: string; readonly kind: string; readonly open: Open },
		challenge: BindingChallenge,
		proof: string,
	) => {
		const { id } = open;
		// A transaction's attempt, never the subject's lockout: guessing it would lock the subject out.
		const left = (await p.transactions.spend(id))?.left;
		if (left === undefined) return unknownTransaction;
		const bound = { transaction: id, kind };
		const passed = await p.transactions.judged(id, () =>
			p.bindingProof.prove(subject, proof, challenge.sealed, bound),
		);
		const judged = { kind: challenge.proof, purpose: open.purpose };
		if (passed) audited("verified", subject, request, judged);
		else audited("verify.failure", subject, request, { ...judged, reason: "invalid" });
		if (passed && left > 0) {
			const kept = await p.transactions.bindingPassed(id, challenge.sealed, { kind, pass: passed });
			return kept ? { passed } : unknownTransaction;
		}
		// The last attempt ends the transaction even when it passes: none would be left to complete a binding.
		if (left === 0) await p.transactions.take(id);
		return passed
			? unknownTransaction
			: jsonAnswer(401, { error: "mfa_invalid", attempts_remaining: left });
	};

	/** The pass for the binding proof, kept or passed now; nothing when none is asked after all; else the answer. */
	const bindingProof = async (
		request: HttpRequest,
		e: Enrolling,
		kind: string,
	): Promise<HttpResponse | { readonly passed?: string }> => {
		const { where } = e;
		const open = "session" in where ? undefined : where;
		// A pass kept for another kind begins nothing here, so the proof is asked again.
		const pass = open?.bindingPassed;
		if (pass?.kind === kind) return { passed: pass.pass };
		const proof = proofOf(request);
		if (open?.bindingChallenge && proof !== undefined)
			return proveSent(request, { subject: e.subject, kind, open }, open.bindingChallenge, proof);
		const until = open?.deadline ?? p.transactions.nextDeadline();
		const sent = await sendBinding(e.subject, until, e.from);
		if (sent === undefined) return {};
		if ("status" in sent) return sent;
		const kept = await keep(e, { bindingChallenge: sent.challenge });
		if (!kept) return unknownTransaction;
		const purpose = open?.purpose ?? "enroll";
		audited("challenge.sent", e.subject, request, { kind: sent.challenge.proof, purpose });
		const asked = {
			error: "mfa_binding_proof_required",
			transaction: kept.id,
			expires_in: kept.expiresIn,
		};
		return jsonAnswer(403, { ...sent.shown, ...asked }, { cookies: kept.cookies });
	};

	/** The challenge route in an enrollment's transaction: sends its binding proof again. */
	const challengeBinding = async (
		request: HttpRequest,
		id: string,
		t: Transaction,
	): Promise<HttpResponse> => {
		const elsewhere = await outsideSession(request, t);
		if (elsewhere) return elsewhere;
		const sent = t.bindingPassed
			? undefined
			: await sendBinding(t.subject, t.deadline, askedFrom(t));
		if (sent === undefined) return jsonAnswer(200, {});
		if ("status" in sent) return sent;
		if (!(await p.transactions.bindingSent(id, sent.challenge))) return unknownTransaction;
		audited("challenge.sent", t.subject, request, {
			kind: sent.challenge.proof,
			purpose: t.purpose,
		});
		return jsonAnswer(200, sent.shown);
	};

	const enroll: Handler = async (request) => {
		const txId = postedTransaction(request);
		if (txId === false) return unknownTransaction;
		const e = await enrolling(request, txId);
		if ("status" in e) return e;
		const kind = field(request, "kind") ?? "";
		const { from } = e;
		const transaction = "session" in e.where ? undefined : e.where.id;
		const begin = (passed?: string) => p.factors.begin(e.subject, kind, passed, transaction, from);
		// Begun without a pass first, mfa judges the kind before a binding proof goes out; one goes out only when asked.
		const asks = await p.bindingProof.asks(e.subject, from);
		let begun = await begin();
		if (asks === "proof" && begun.kind === "binding-proof-required") {
			const proved = await bindingProof(request, e, kind);
			if ("status" in proved) return proved;
			begun = await begin(proved.passed);
		}
		// Only a login's ask is closed so: a factor counts by now, and the password alone adds none.
		if (begun.kind === "first-binding-closed") return loginRequired;
		if (begun.kind !== "begun") return refusals[begun.kind] ?? unknownKind;
		const kept = await keep(e, { pending: begun.pending });
		if (!kept) return unknownTransaction;
		const at = { transaction: kept.id, expires_in: kept.expiresIn };
		return jsonAnswer(200, { ...begun.show, ...at }, { cookies: kept.cookies });
	};

	const complete: Handler = async (request) => {
		const txId = postedTransaction(request);
		if (!txId) return unknownTransaction;
		const t = (await p.transactions.find(request, txId))?.transaction;
		if (!t?.pending || (t.purpose !== "enroll" && t.purpose !== "enroll-login"))
			return unknownTransaction;
		if (await revokedSince(p.revocation, t)) {
			await p.transactions.take(txId);
			return loginRequired;
		}
		const elsewhere = await outsideSession(request, t);
		if (elsewhere) return elsewhere;
		// A label is optional, but one sent that is not a string or not of mfa's shape is refused.
		const label = field(request, "label");
		if (request.mistyped?.has("label") || (label !== undefined && !isLabel(label)))
			return invalidLabel;
		const left = (await p.transactions.spend(txId))?.left;
		if (left === undefined) return unknownTransaction;
		const proof = proofOf(request) ?? "";
		// Kept: inside the callback below, the check above no longer narrows it.
		const pending = t.pending;
		const proved = await p.transactions.judged(txId, () =>
			p.factors.provePending(t.subject, pending, proof),
		);
		if (proved.kind === "unknown") return unknownTransaction;
		if (proved.kind !== "valid") {
			if (left === 0) await p.transactions.take(txId);
			return jsonAnswer(401, { error: "mfa_invalid", attempts_remaining: left });
		}
		if (!(await p.transactions.take(txId))) return unknownTransaction;
		// Checked again just before the write, to answer early: a reset since the binding began, or a
		// revocation once complete, is fenced inside mfa's write in any case.
		if (await revokedSince(p.revocation, t)) return loginRequired;
		const bound = await p.factors.bind(t.subject, pending, proved.state, label, askedFrom(t));
		// A reset or a revocation since the binding began, which ended its sessions too.
		if (bound.kind === "fenced") return loginRequired;
		// A first binding another factor beat: a login asks again, a session is told of the conflict.
		if (bound.kind === "first-binding-closed") {
			return t.purpose === "enroll-login" ? loginRequired : enrollmentConflict;
		}
		if (bound.kind !== "bound") return refusals[bound.kind] ?? unknownTransaction;
		/** Takes back the codes no one will see; read just before, a reset or a revocation in between leaves them, unseen all the same. */
		const takeBack = async () => {
			const id = bound.recoveryCodesFactor;
			if (id) await p.factors.remove(t.subject, id, await p.factors.fenceOf(t.subject));
		};
		// The fence guards the write, not the showing: a revocation complete by now leaves the codes unseen.
		if (bound.recoveryCodesFactor !== undefined && (await revokedSince(p.revocation, t))) {
			await takeBack().catch(() => undefined);
			return loginRequired;
		}
		const codes = bound.recoveryCodes === undefined ? {} : { recovery_codes: bound.recoveryCodes };
		const body = { factor: bound.factor, ...codes };
		// A first factor bound on the password alone counts from the next sign-in: binding it during a
		// login never finishes that login.
		if (!t.proved) return jsonAnswer(200, body, { cookies: [p.transactions.cleared()] });
		// Bound on a binding proof, it counts at once by its first proof: the login goes on, or the session is raised.
		// Either can fail after the codes were made: then they go, as no one would ever see them.
		const shown = async (answer: () => Promise<HttpResponse>) => {
			try {
				const answered = await answer();
				// The last wait before the codes go out is the revocation's: none may come after it.
				if (bound.recoveryCodesFactor !== undefined && (await revokedSince(p.revocation, t))) {
					await takeBack().catch(() => undefined);
					return loginRequired;
				}
				return answered;
			} catch (error) {
				// One that cannot go stays unseen, as before; the failure answered is the first.
				await takeBack().catch(() => undefined);
				throw error;
			}
		};
		if (t.purpose === "enroll-login") return shown(() => p.resume(request, t, proved.amr, body));
		return shown(async () => {
			const raised = await p.sessions.raise(request, proved.amr);
			const cookies = [...(raised?.cookies ?? []), p.transactions.cleared()];
			return jsonAnswer(200, body, { cookies });
		});
	};

	return { enroll, complete, challengeBinding };
}
