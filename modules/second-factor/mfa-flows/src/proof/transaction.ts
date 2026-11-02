import { jsonAnswer } from "@mod/http";
import {
	type Handler,
	loginRequired,
	revokedSince,
	unknownTransaction,
} from "../requests/requests.ts";
import type { ProofParts } from "./proof.ts";

/** What a transaction is: its purpose, the factors held, the attempts and the time left. */
export function transactionWith(p: ProofParts): Handler {
	return async (request) => {
		const named = request.headers.get("mfa-transaction");
		// Named by no header, it is the browser's own, by its cookie: the page a navigation lands on asks so.
		const txId = named ?? p.transactions.carried(request);
		const found = await p.transactions.find(request, txId);
		if (!found) return unknownTransaction;
		if (await revokedSince(p.revocation, found.transaction)) return loginRequired;
		return jsonAnswer(200, {
			...(named === undefined && txId !== undefined ? { transaction: txId } : {}),
			purpose: found.transaction.purpose,
			factors: await p.factors.held(found.transaction.subject),
			attempts_remaining: found.transaction.attemptsLeft,
			expires_in: Math.floor(found.leftMs / 1000),
		});
	};
}

/** A step-up started for the session the request enters, where it holds a factor. */
export function stepUpWith(p: ProofParts): Handler {
	return async (request) => {
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
}
