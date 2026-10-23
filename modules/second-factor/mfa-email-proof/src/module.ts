import { defineModule } from "@mod/kernel";
import { bindingProof, bindingProofs } from "@mod/mfa-binding-proof";
import { mailedCodesIn } from "@mod/mfa-email";
import { users } from "@mod/users";
import { accountEmailProof } from "./proof.ts";

export default defineModule({ name: "mfa-email-proof", replicaSafe: true }, (m) => [
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
]);
