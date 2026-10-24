import { defineModule } from "@mod/kernel";
import { resetParts } from "@mod/mfa-reset";
import { passkeyResetPart } from "@mod/passkey-reset";

/** The name the reset's audit gives this part (`parts`, `partsStopped`), as operators read it. */
const name = "passkeys";

export default defineModule({ name: "mfa-reset-passkeys", takes: [passkeyResetPart] }, (m) => [
	m.contribute(resetParts).by(async (c) => {
		const part = await c.get(passkeyResetPart);
		// The two answer alike: done with how many went, stopped, or a failure thrown.
		return { name, remove: (subject) => part.passkeys(subject) };
	}),
]);
