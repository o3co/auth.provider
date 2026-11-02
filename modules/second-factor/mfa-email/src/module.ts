import { type BuildContext, defineModule } from "@mod/kernel";
import { mail, mailPurposes } from "@mod/mail";
import { bindingProof, bindingProofs } from "@mod/mfa-binding-proof";
import { factorKinds } from "@mod/mfa-extensions";
import { subjectAttributes } from "@mod/subject-attributes";
import { users } from "@mod/users";
import { purposes } from "./contract.ts";
import { emailFactor } from "./kind.ts";
import { type Settings, section } from "./section.ts";

/** The binding proof of the account's address, which mfa-email-proof contributes. */
const accountEmail = "account-email";

export default defineModule(
	{
		name: "mfa-email",
		section,
		replicaSafe: true,
		takes: [mail, bindingProof, bindingProofs, subjectAttributes, users],
	},
	(m) => [
		m.contribute(factorKinds).by(async (c: BuildContext<Settings>) => {
			// A code by email comes with the proof of the account's address before a first binding, and
			// with mfa-binding-proof, which hears it and gates the binding: named late, so boot refuses
			// without it, whatever contributes the proof. Without either a first factor binds unproved.
			c.late(bindingProof);
			const proofs = await c.collect(bindingProofs);
			if (!proofs.some((proof) => proof.name === accountEmail)) {
				c.refuse(
					"mfa-email",
					"a code by email is composed without mfa-email-proof, which proves the account's address before a first binding: compose it",
				);
			}
			// The operator's choice, yet said at every start: the mailbox alone meets a second factor.
			if (c.section["adds-second-factor"]) {
				c.log.warn("mfa-email.counts_as_second_factor", {
					reason: "a code by mail meets a required second factor",
				});
			}
			return emailFactor({
				mail: await c.get(mail),
				users: await c.get(users),
				// Late: session's own build asks mfa, which asks this kind.
				attributes: c.late(subjectAttributes),
				addsSecondFactor: c.section["adds-second-factor"],
				codeMs: c.section["code-lifetime"] * 1000,
				now: c.clock.now,
				random: c.random.bytes,
			});
		}),
		...Object.values(purposes).map((purpose) => m.contribute(mailPurposes).by(() => ({ purpose }))),
	],
);
