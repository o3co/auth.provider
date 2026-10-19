import { contract, extensionPoint } from "@mod/kernel";
import type { EnrollmentFlow, FlowParts } from "./seams/seams.ts";

/** An operator's reset of a subject's second factors, for the embedder that has verified who asks. */
export interface MfaReset {
	/** Answers how many factors went; rejects as unavailable when a step cannot be done, and running it again finishes it. */
	reset(subject: string, options?: { readonly requestedBy?: string }): Promise<number>;
}

export const mfaReset = contract<MfaReset>("mfa-flows.reset");

export type { Handler } from "./routing.ts";
export type { EnrollmentFlow, FlowParts } from "./seams/seams.ts";
export type {
	ByPurpose,
	Challenge,
	HeldFacts,
	Transaction,
	TransactionBase,
} from "./transactions/records.ts";
export type { Transactions } from "./transactions/transactions.ts";

/** The enrollment routes' handlers, from the module binding factors: at most one contribution. */
export const enrollmentFlow = extensionPoint<EnrollmentFlow>("mfa-flows.enrollment-flow", {
	multiplicity: "keyed",
	keyOf: () => "enrollment-flow",
});

/** What this package gives the module binding factors; built without asking for an enrollment flow. */
export const flowParts = contract<FlowParts>("mfa-flows.parts");

export * from "./store.ts";
