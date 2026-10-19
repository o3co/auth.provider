import type { Audit } from "@mod/audit";
import type { HttpRequest, HttpResponse } from "@mod/http";
import type { LockoutPolicy } from "@mod/rate-limit";
import type { resumeOver } from "../proof/proof.ts";
import { auditedBy } from "../recording/recording.ts";
import * as routing from "../routing.ts";
import { lockoutName } from "../section.ts";
import type { Transaction } from "../transactions/records.ts";
import { askedFrom, type Transactions } from "../transactions/transactions.ts";

/** The enrollment routes' handlers, and the answer to a challenge in an enrollment's transaction. */
export interface EnrollmentFlow {
	readonly enroll: routing.Handler;
	readonly complete: routing.Handler;
	challenge(request: HttpRequest, id: string, t: Transaction): Promise<HttpResponse>;
}

/** What the module binding factors takes of this package; each user narrows it with `Pick`. */
export interface FlowParts {
	readonly transactions: Transactions;
	readonly askedFrom: typeof askedFrom;
	readonly resume: ReturnType<typeof resumeOver>;
	readonly record: ReturnType<typeof auditedBy>;
	readonly answers: Pick<typeof routing, "unknownTransaction" | "loginRequired" | "unavailable">;
	readonly requests: Pick<
		typeof routing,
		"field" | "proofOf" | "postedTransaction" | "revokedSince" | "managing"
	>;
	readonly lockout: { readonly name: string; readonly policy: LockoutPolicy };
}

/** The parts, from what the package already builds: none of it asks for an enrollment flow. */
export const flowPartsOf = (parts: {
	readonly transactions: Transactions;
	readonly resume: ReturnType<typeof resumeOver>;
	readonly audit: Pick<Audit, "record">;
	readonly policy: LockoutPolicy;
}): FlowParts => ({
	transactions: parts.transactions,
	askedFrom,
	resume: parts.resume,
	record: auditedBy(parts.audit),
	answers: {
		unknownTransaction: routing.unknownTransaction,
		loginRequired: routing.loginRequired,
		unavailable: routing.unavailable,
	},
	requests: {
		field: routing.field,
		proofOf: routing.proofOf,
		postedTransaction: routing.postedTransaction,
		revokedSince: routing.revokedSince,
		managing: routing.managing,
	},
	lockout: { name: lockoutName, policy: parts.policy },
});
