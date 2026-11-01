import type { FactorBinding } from "@mod/mfa-binding";
import type { BindingProofs } from "@mod/mfa-binding-proof";
import type { FlowParts } from "@mod/mfa-flows";
import type { FactorManaging } from "@mod/mfa-managing";
import type { Sessions } from "@mod/session";
import type { SubjectRevocation } from "@mod/subject-revocation";

/** What an enrollment takes: `mfa-flows`' parts, and the contracts it asks itself. */
export interface EnrollmentParts {
	/** Whether a factor of the kind meets a required second factor, as its kind says. */
	readonly counts: (kind: string) => boolean;
	readonly binding: FactorBinding;
	/** The recovery codes a binding leaves due. */
	readonly managing: Pick<FactorManaging, "reissue">;
	readonly bindingProof: BindingProofs;
	readonly sessions: Sessions;
	readonly revocation: SubjectRevocation;
	readonly flow: Pick<
		FlowParts,
		"transactions" | "askedFrom" | "resumeWith" | "record" | "answers" | "requests"
	>;
}
