import { type HttpRequest, jsonAnswer } from "@mod/http";
import {
	loginRequired,
	postedTransaction,
	revokedSince,
	unknownTransaction,
} from "../requests/requests.ts";
import type { Transaction } from "../transactions/records.ts";
import type { ProofParts } from "./proof.ts";

/** A transaction a factor is proved in: a login's or a step-up's. */
export const proved = (
	t: Transaction,
): t is Transaction & { readonly purpose: "login" | "step-up" } =>
	t.purpose === "login" || t.purpose === "step-up";
/** The challenge route also takes an enrollment's transaction. */
export const anyPurpose = (_: Transaction): _ is Transaction => true;

export const unknownFactor = jsonAnswer(400, {
	error: "invalid_request",
	error_description: "unknown factor",
});

/** The transaction a POST names, of a purpose the route takes, or the answer refusing it. */
export function provingWith(p: Pick<ProofParts, "transactions" | "sessions" | "revocation">) {
	return async <T extends Transaction>(request: HttpRequest, takes: (t: Transaction) => t is T) => {
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
}

export type Proving = ReturnType<typeof provingWith>;
