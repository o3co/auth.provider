import { defineModule } from "@mod/kernel";
import { factors } from "@mod/mfa";
import { bindingProof } from "@mod/mfa-binding-proof";
import { enrollmentFlow, flowParts } from "@mod/mfa-flows";
import { sessions } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { bindingProofOver } from "./binding-proof/binding-proof.ts";
import { completionOver } from "./completion/completion.ts";
import { placeOver } from "./place.ts";

export default defineModule({ name: "mfa-enrollment" }, (m) => [
	m.contribute(enrollmentFlow).by(async (c) => {
		const parts = {
			factors: await c.get(factors),
			bindingProof: await c.get(bindingProof),
			sessions: await c.get(sessions),
			revocation: await c.get(subjectRevocation),
			flow: await c.get(flowParts),
		};
		const place = placeOver(parts);
		const proofs = bindingProofOver(parts, place);
		const { enroll, complete } = completionOver(parts, place, proofs);
		return { enroll, complete, challenge: proofs.challengeBinding };
	}),
]);
