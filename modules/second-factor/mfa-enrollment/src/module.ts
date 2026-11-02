import { defineModule } from "@mod/kernel";
import { factorBinding } from "@mod/mfa-binding";
import { bindingProof } from "@mod/mfa-binding-proof";
import { factorKinds } from "@mod/mfa-extensions";
import { enrollmentFlow, flowParts } from "@mod/mfa-flows";
import { factorManaging } from "@mod/mfa-managing";
import { sessions } from "@mod/session";
import { subjectRevocation } from "@mod/subject-revocation";
import { bindingProofOver } from "./binding-proof/binding-proof.ts";
import { completionOver } from "./completion/completion.ts";
import { placeOver } from "./place.ts";

export default defineModule(
	{
		name: "mfa-enrollment",
		replicaSafe: true,
		takes: [
			bindingProof,
			factorKinds,
			flowParts,
			factorBinding,
			factorManaging,
			sessions,
			subjectRevocation,
		],
	},
	(m) => [
		m.contribute(enrollmentFlow).by(async (c) => {
			const kinds = await c.collect(factorKinds);
			const parts = {
				counts: (kind: string) => kinds.some((k) => k.kind === kind && k.counts),
				binding: await c.get(factorBinding),
				managing: await c.get(factorManaging),
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
	],
);
