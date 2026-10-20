import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import type { AskedFrom } from "@mod/mfa-extensions";
import type { Transaction } from "@mod/mfa-flows";
import { type BindingChallenge, heldOf, holding } from "../held.ts";
import type { EnrollmentParts } from "../parts.ts";
import type { Enrolling, Open, Place } from "../place.ts";

/** A binding proof: asking it, judging what was sent for it, and sending it again in an enrollment's transaction. */
export function bindingProofOver(p: EnrollmentParts, place: Place) {
	const { transactions, askedFrom, record: audited } = p.flow;
	const { unknownTransaction } = p.flow.answers;
	const { proofOf } = p.flow.requests;
	const { outsideSession, keep } = place;
	const binding = holding(transactions);
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
		const left = (await transactions.spend(id))?.left;
		if (left === undefined) return unknownTransaction;
		const bound = { transaction: id, kind };
		const passed = await transactions.judged(id, () =>
			p.bindingProof.prove(subject, proof, challenge.sealed, bound),
		);
		const judged = { kind: challenge.proof, purpose: open.purpose };
		if (passed) audited("verified", subject, request, judged);
		else audited("verify.failure", subject, request, { ...judged, reason: "invalid" });
		if (passed && left > 0) {
			const kept = await binding.bindingPassed(id, challenge.sealed, { kind, pass: passed });
			return kept ? { passed } : unknownTransaction;
		}
		// The last attempt ends the transaction even when it passes: none would be left to complete a binding.
		if (left === 0) await transactions.take(id);
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
		const until = open?.deadline ?? transactions.nextDeadline();
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
		const sent = heldOf(t).bindingPassed
			? undefined
			: await sendBinding(t.subject, t.deadline, askedFrom(t));
		if (sent === undefined) return jsonAnswer(200, {});
		if ("status" in sent) return sent;
		if (!(await binding.bindingSent(id, sent.challenge))) return unknownTransaction;
		audited("challenge.sent", t.subject, request, {
			kind: sent.challenge.proof,
			purpose: t.purpose,
		});
		return jsonAnswer(200, sent.shown);
	};

	return { bindingProof, challengeBinding };
}
