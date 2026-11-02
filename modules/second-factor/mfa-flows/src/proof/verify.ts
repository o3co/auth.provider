import { type HttpRequest, type HttpResponse, jsonAnswer } from "@mod/http";
import { isUnavailable } from "@mod/kernel";
import type { auditedBy } from "../recording/recording.ts";
import {
	field,
	type Handler,
	loginRequired,
	proofOf,
	unknownTransaction,
} from "../requests/requests.ts";
import { lockoutName } from "../section.ts";
import type { ProofParts, resumeOver } from "./proof.ts";
import { type Proving, proved, unknownFactor } from "./proving.ts";

type Proved = { readonly amr: readonly string[] };

/** A factor's proof judged, then the login resumed or the session raised. */
export function verifyWith(
	p: ProofParts,
	proving: Proving,
	audited: ReturnType<typeof auditedBy>,
	resumeLogin: ReturnType<typeof resumeOver>,
): Handler {
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

	return async (request) => {
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
}
