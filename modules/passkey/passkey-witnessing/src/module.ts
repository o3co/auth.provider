import { audit } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { passkeyWitnesses } from "@mod/passkey-witness";
import { passkeyReading, passkeyWitnessing } from "@mod/passkeys";
import { backfillWith } from "./backfill.ts";
import { passkeyBackfill } from "./contract.ts";
import { witnessingOver } from "./witnessing.ts";

export default defineModule(
	{ name: "passkey-witnessing", takes: [audit, passkeyReading, passkeyWitnesses] },
	(m) => [
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
		m.provide(passkeyBackfill).by(async (c) => {
			const [witness, ...more] = await c.collect(passkeyWitnesses);
			if (!witness || more.length > 0) {
				return c.refuse("passkey-witnessing", "exactly one passkey witness must be composed");
			}
			// Late: passkeys asks this module's witnessing as it is built.
			const reading = c.late(passkeyReading);
			return {
				settle: backfillWith({
					witness,
					holding: (subject) => reading().writtenHolding(subject),
					token: () => Buffer.from(c.random.bytes(16)).toString("base64url"),
				}),
			};
		}),
	],
);
