import { audit } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { flowParts } from "@mod/mfa-flows";
import { factorManaging } from "@mod/mfa-managing";
import { factorReading } from "@mod/mfa-reading";
import { lockouts } from "@mod/rate-limit";
import { revocations } from "@mod/subject-revocation";
import { mfaReset, resetCandidates, resetParts } from "./contract.ts";
import { resetOver } from "./reset.ts";

export default defineModule({ name: "mfa-reset" }, (m) => [
	m.provide(mfaReset).by(async (c) =>
		resetOver({
			factors: await c.get(factorManaging),
			revocations: await c.get(revocations),
			lockouts: await c.get(lockouts),
			lockout: (await c.get(flowParts)).lockout,
			audit: await c.get(audit),
			log: c.log,
			parts: await c.collect(resetParts),
		}),
	),
	m.provide(resetCandidates).by(async (c) => {
		const reading = await c.get(factorReading);
		return { unclaimed: (subject) => reading.unclaimedWritten(subject) };
	}),
]);
