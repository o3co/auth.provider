import { audit } from "@mod/audit";
import { type BuildContext, contract, defineModule } from "@mod/kernel";
import { passkeyHolders } from "@mod/passkeys";
import { revocations } from "@mod/subject-revocation";
import { passkeyReset, passkeyResetPart } from "./contract.ts";
import { resetOver } from "./reset.ts";

/** The reset and its passkeys' step, made once over the same holdings. */
const made = contract<ReturnType<typeof resetOver>>("passkey-reset.made");
const madeOf = (c: BuildContext<unknown>) => c.get(made);

export default defineModule(
	{ name: "passkey-reset", takes: [audit, passkeyHolders, revocations] },
	(m) => [
		m.provide(made).by(async (c) =>
			resetOver({
				revocations: await c.get(revocations),
				holders: await c.get(passkeyHolders),
				audit: await c.get(audit),
				log: c.log,
			}),
		),
		m.provide(passkeyReset).by(async (c) => (await madeOf(c)).reset),
		m.provide(passkeyResetPart).by(async (c) => (await madeOf(c)).part),
	],
);
