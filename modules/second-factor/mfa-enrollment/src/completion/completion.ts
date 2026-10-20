import { type HttpResponse, jsonAnswer } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import { type Factors, isLabel } from "@mod/mfa";
import type { Handler } from "@mod/mfa-flows";
import type { bindingProofOver } from "../binding-proof/binding-proof.ts";
import { heldOf } from "../held.ts";
import type { EnrollmentParts } from "../parts.ts";
import type { Place } from "../place.ts";

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
const factorLimit = jsonAnswer(409, { error: "mfa_factor_limit" });
/** What `mfa` refuses a binding with, as answered here; anything else refuses it too. */
const refusals: Readonly<Partial<Record<Refusal, HttpResponse>>> = {
	full: factorLimit,
	duplicate: jsonAnswer(409, { error: "mfa_factor_duplicate" }),
	limited: jsonAnswer(429, { error: "rate_limited" }),
	refused: jsonAnswer(403, { error: "mfa_factor_refused" }),
	"binding-proof-required": jsonAnswer(403, { error: "mfa_binding_proof_required" }),
};
const enrollmentConflict = jsonAnswer(409, { error: "mfa_enrollment_conflict" });
const invalidLabel = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "invalid label",
});

/** Begins a binding, and completes it with its first proof. */
export function completionOver(
	p: EnrollmentParts,
	place: Place,
	proofs: Pick<ReturnType<typeof bindingProofOver>, "bindingProof">,
) {
	const { transactions, askedFrom } = p.flow;
	const { unknownTransaction, loginRequired, unavailable } = p.flow.answers;
	const { resume } = p.flow;
	const { field, postedTransaction, proofOf, revokedSince } = p.flow.requests;
	const { enrolling, outsideSession, keep } = place;
	const { bindingProof } = proofs;
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
		const t = (await transactions.find(request, txId))?.transaction;
		if (!heldOf(t).pending || !t || (t.purpose !== "enroll" && t.purpose !== "enroll-login"))
			return unknownTransaction;
		if (await revokedSince(p.revocation, t)) {
			await transactions.take(txId);
			return loginRequired;
		}
		const elsewhere = await outsideSession(request, t);
		if (elsewhere) return elsewhere;
		// A label is optional, but one sent that is not a string or not of mfa's shape is refused.
		const label = field(request, "label");
		if (request.mistyped?.has("label") || (label !== undefined && !isLabel(label)))
			return invalidLabel;
		const left = (await transactions.spend(txId))?.left;
		if (left === undefined) return unknownTransaction;
		const proof = proofOf(request) ?? "";
		// Kept: inside the callback below, the check above no longer narrows it.
		const pending = heldOf(t).pending ?? "";
		const proved = await transactions.judged(txId, () =>
			p.factors.provePending(t.subject, pending, proof),
		);
		if (proved.kind === "unknown") return unknownTransaction;
		if (proved.kind !== "valid") {
			if (left === 0) await transactions.take(txId);
			return jsonAnswer(401, { error: "mfa_invalid", attempts_remaining: left });
		}
		if (!(await transactions.take(txId))) return unknownTransaction;
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
		const factor = { factor: bound.factor };
		/** The answer, with the recovery codes where they are due: written only now, just before they go out. */
		const shown = async (): Promise<object | HttpResponse> => {
			if (!bound.codesDue) return factor;
			// Checked before the write too: the fence stops it only where a revocation moves it (`mfa-revocation`).
			if (await revokedSince(p.revocation, t)) return loginRequired;
			const reissued = await p.factors.reissue(t.subject, bound.fence);
			// A reset or a revocation since the binding began, or the factor gone meanwhile: no one sees codes.
			if (reissued.kind === "fenced" || reissued.kind === "no-qualifying-factor")
				return loginRequired;
			// Another factor took the place the binding kept: the factor stands, and codes can be reissued.
			if (reissued.kind === "full") return factorLimit;
			// Left is `unknown-kind`, which cannot come: codes are due only where a way back is composed.
			if (reissued.kind !== "reissued") return factor;
			// The last wait before the codes go out is the revocation's: none may come after it.
			if (await revokedSince(p.revocation, t)) return loginRequired;
			return { ...factor, recovery_codes: reissued.codes };
		};
		const isAnswer = (made: object): made is HttpResponse => "status" in made;
		// A first factor bound on the password alone counts from the next sign-in: binding it during a
		// login never finishes that login.
		if (!heldOf(t).proved) {
			const made = await shown();
			if (isAnswer(made)) return made;
			return jsonAnswer(200, made, { cookies: [transactions.cleared()] });
		}
		// Bound on a binding proof, it counts at once by its first proof: the login goes on, its codes
		// made once it opened, or the session is raised, and its codes made once it is.
		if (t.purpose === "enroll-login") return resume(request, t, proved.amr, shown);
		const raised = await p.sessions.raise(request, proved.amr);
		const cookies = [...(raised?.cookies ?? []), transactions.cleared()];
		// A raise not written leaves the factor to count from the next sign-in: no codes for it now.
		if (!raised?.raised) return jsonAnswer(200, factor, { cookies });
		let made: object | HttpResponse;
		try {
			made = await shown();
		} catch (error) {
			// The raise retired the old cookie: the new one goes out with the failure.
			if (isUnavailable(error)) return { ...unavailable, cookies };
			throw error;
		}
		if (made === factorLimit) return { ...factorLimit, cookies };
		if (isAnswer(made)) return made;
		return jsonAnswer(200, made, { cookies });
	};

	return { enroll, complete };
}
