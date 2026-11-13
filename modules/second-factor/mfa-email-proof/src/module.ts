import { mailedCodesIn, mailedTakes } from "@mod/account-mail-code";
import { defineModule } from "@mod/kernel";
import { mailPurposes } from "@mod/mail";
import { bindingProof, bindingProofs } from "@mod/mfa-binding-proof";
import { users } from "@mod/users";
import { accountEmailProof } from "./proof.ts";
import { purposes } from "./purposes.ts";

/** What the proof takes: `mailedCodesIn`'s, `users`, and `bindingProof` late. */
const takes = [...mailedTakes, users, bindingProof];

export default defineModule({ name: "mfa-email-proof", replicaSafe: true, takes }, (m) => [
	m.contribute(bindingProofs).by(async (c) => {
		// Named late, as it collects this proof: boot refuses where it is not composed to hear it.
		c.late(bindingProof);
		return accountEmailProof({
			mailed: await mailedCodesIn(c),
			users: await c.get(users),
			log: c.log,
			now: c.clock.now,
			random: c.random.bytes,
		});
	}),
	...Object.values(purposes).map((purpose) => m.contribute(mailPurposes).by(() => ({ purpose }))),
]);
