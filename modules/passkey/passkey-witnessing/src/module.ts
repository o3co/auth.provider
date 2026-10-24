import { audit } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { passkeyWitnessing } from "@mod/passkeys";
import { witnessingOver } from "./witnessing.ts";

export default defineModule({ name: "passkey-witnessing" }, (m) => [
	m.contribute(passkeyWitnessing).by(async (c) => {
		const [witness, ...more] = await c.collect(passkeyWitnesses);
		if (!witness || more.length > 0) {
			return c.refuse("passkey-witnessing", "exactly one passkey witness must be composed");
		}
		return witnessingOver({
			witness,
			audit: await c.get(audit),
			log: c.log,
			token: () => Buffer.from(c.random.bytes(16)).toString("base64url"),
		});
	}),
]);
