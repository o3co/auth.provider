import type { Factors } from "@mod/mfa";
import type { BindingProofs } from "@mod/mfa-binding-proof";
import type { FlowParts } from "@mod/mfa-flows";
import type { Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";

/** What an enrollment takes: `mfa-flows`' parts, and the contracts it asks itself. */
export interface EnrollmentParts {
	readonly factors: Factors;
	readonly bindingProof: BindingProofs;
	readonly sessions: Sessions;
	readonly revocation: SubjectRevocation;
	readonly flow: Pick<
		FlowParts,
		"transactions" | "askedFrom" | "resumeWith" | "record" | "answers" | "requests"
	>;
}
