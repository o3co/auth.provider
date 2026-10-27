import type { SelectionMode } from "@mod/claims-selection";
import { contract } from "@mod/kernel";

/** What a revocation run did: nothing while not draining; else the families revoked, those run out, and what failed. */
export type RevocationRun =
	| { readonly kind: "not-draining"; readonly mode: SelectionMode }
	| {
			readonly kind: "run";
			readonly revoked: number;
			/** Families whose selection ran out, so the family did too: unlisted, not revoked. */
			readonly expired: number;
			readonly failed: {
				/** Parts of the list that could not be read. */
				readonly shards: number;
				readonly reads: number;
				readonly revocations: number;
				readonly removals: number;
			};
	  };

/** Revokes, before going back to a release before 0.19, every refresh family whose selection holds constraints. */
export interface ConstrainedFamilyRevocation {
	/** Only while claims-selection is draining; what fails stays listed, so a run again finishes it. */
	run(): Promise<RevocationRun>;
}

export const constrainedFamilyRevocation =
	contract<ConstrainedFamilyRevocation>("claims-revocation");
