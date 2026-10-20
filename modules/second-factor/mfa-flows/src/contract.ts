import { contract, extensionPoint } from "@mod/kernel";
import type { EnrollmentFlow, FlowParts } from "./seams/seams.ts";

export type { Handler } from "./routing.ts";
export type { EnrollmentFlow, FlowParts, FlowTransactions, ResumeMade } from "./seams/seams.ts";
export type {
	ByPurpose,
	Challenge,
	HeldFacts,
	Started,
	Transaction,
	TransactionBase,
} from "./transactions/records.ts";

/** The enrollment routes' handlers, from the module binding factors: exactly one contribution. */
export const enrollmentFlow = extensionPoint<EnrollmentFlow>("mfa-flows.enrollment-flow", {
	multiplicity: "one",
});

/** What this package gives the module binding factors; built without asking for an enrollment flow. */
export const flowParts = contract<FlowParts>("mfa-flows.parts");

export * from "./store.ts";
