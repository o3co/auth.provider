import type { HttpRequest, HttpResponse } from "@mod/http";
import type { AskedFrom } from "@mod/mfa-extensions";
import type { Transaction } from "@mod/mfa-flows";
import { type Binding, type BindingChallenge, heldOf, holding } from "./held.ts";
import type { EnrollmentParts } from "./parts.ts";

/** The transaction an enrollment goes on in, and how far its binding proof went. */
export interface Open
	extends Pick<Transaction, "purpose" | "deadline">,
		Pick<Binding, "bindingChallenge" | "bindingPassed"> {
	readonly id: string;
	readonly expiresIn: number;
}

/** Whose binding begins, and where: its transaction, or the session whose own starts once it holds something. */
export interface Enrolling {
	readonly subject: string;
	readonly where: Open | { readonly session: string };
	/** Whom `mfa` is asked for: the session, or the transaction's login or session. */
	readonly from: AskedFrom;
}

/** Where an enrollment goes on: in its transaction, or in the session that starts its own. */
export function placeOver(p: EnrollmentParts) {
	const { transactions, askedFrom } = p.flow;
	const { unknownTransaction, loginRequired } = p.flow.answers;
	const { managing, revokedSince } = p.flow.requests;
	const binding = holding(transactions);
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
		const found = await transactions.find(request, txId);
		if (!found) return unknownTransaction;
		const t = found.transaction;
		if (t.purpose !== "enroll-login" && t.purpose !== "enroll") return unknownTransaction;
		if (await revokedSince(p.revocation, t)) {
			await transactions.take(txId);
			return loginRequired;
		}
		const elsewhere = await outsideSession(request, t);
		if (elsewhere) return elsewhere;
		const expiresIn = Math.floor(found.leftMs / 1000);
		return {
			subject: t.subject,
			where: { ...t, ...heldOf(t), id: txId, expiresIn },
			from: askedFrom(t),
		};
	};

	/** Holds what the enrollment keeps, in its transaction or one started in the session: where, or none when no longer in use. */
	const keep = async (
		e: Enrolling,
		held: { readonly pending: string } | { readonly bindingChallenge: BindingChallenge },
	) => {
		const { where } = e;
		if ("session" in where) {
			const subject = e.subject;
			return transactions.start({ subject, purpose: "enroll", handle: where.session, held });
		}
		const kept =
			"pending" in held
				? await binding.hold(where.id, held.pending)
				: await binding.bindingSent(where.id, held.bindingChallenge);
		return kept ? { id: where.id, expiresIn: where.expiresIn, cookies: [] } : undefined;
	};

	return { outsideSession, enrolling, keep };
}

export type Place = ReturnType<typeof placeOver>;
