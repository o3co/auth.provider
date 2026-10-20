import type { Audit } from "@mod/audit";
import type { HttpRequest, HttpResponse } from "@mod/http";
import type { AskedFrom } from "@mod/mfa-extensions";
import type { LockoutPolicy } from "@mod/rate-limit";
import type { Session, Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";
import type { resumeOver } from "../proof/proof.ts";
import { auditedBy } from "../recording/recording.ts";
import * as routing from "../routing.ts";
import { lockoutName } from "../section.ts";
import type { ByPurpose, Started, Transaction } from "../transactions/records.ts";
import { askedFrom, type Transactions } from "../transactions/transactions.ts";

/** The enrollment routes' handlers, and the answer to a challenge in an enrollment's transaction. */
export interface EnrollmentFlow {
	readonly enroll: routing.Handler;
	readonly complete: routing.Handler;
	challenge(request: HttpRequest, id: string, t: Transaction): Promise<HttpResponse>;
}

/** A transaction's lifecycle, as the module binding factors uses it; what it holds is its own, never read here. */
export interface FlowTransactions {
	start(record: Started): Promise<{
		readonly id: string;
		readonly deadline: number;
		readonly expiresIn: number;
		readonly cookies: readonly string[];
	}>;
	nextDeadline(): number;
	find(
		request: HttpRequest,
		id: string | undefined,
	): Promise<{ readonly transaction: Transaction; readonly leftMs: number } | undefined>;
	spend(id: string): Promise<{ readonly left: number } | undefined>;
	judged<T>(id: string, judge: () => Promise<T>): Promise<T>;
	take(id: string): Promise<boolean>;
	keep(
		id: string,
		change: (held: unknown) => unknown,
	): Promise<{ readonly held: unknown } | undefined>;
	cleared(): string;
}

/** What the module binding factors takes of this package; each user narrows it with `Pick`. */
export interface FlowParts {
	readonly transactions: FlowTransactions;
	/** Whom `mfa`'s kinds are asked for, by the transaction's purpose. */
	askedFrom(t: ByPurpose): AskedFrom;
	/** Goes on with a held login, adding what was proved to its amr and what `carried` makes to its answer, made once it opens; a response it makes closes the session. */
	resume(
		request: HttpRequest,
		t: Transaction & { readonly purpose: "login" | "enroll-login" },
		proved: readonly string[],
		carried?: () => Promise<object | HttpResponse>,
	): Promise<HttpResponse>;
	/** Records `mfa.<kind>` through this package's declaration, with the request's source. */
	record(
		kind: "challenge.sent" | "verified" | "verify.failure",
		subject: string,
		request: HttpRequest,
		attributes: Record<string, string>,
	): void;
	readonly answers: {
		readonly unknownTransaction: HttpResponse;
		readonly loginRequired: HttpResponse;
		readonly unavailable: HttpResponse;
	};
	readonly requests: {
		field(request: HttpRequest, name: string): string | undefined;
		proofOf(request: HttpRequest): string | undefined;
		postedTransaction(request: HttpRequest): string | false | undefined;
		revokedSince(revocation: Pick<SubjectRevocation, "check">, t: Transaction): Promise<boolean>;
		managing(sessions: Sessions, request: HttpRequest): Promise<Session | HttpResponse>;
	};
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
