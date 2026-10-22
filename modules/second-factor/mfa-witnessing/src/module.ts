import { audit } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { witnessing } from "@mod/mfa-extensions";
import { factorReading } from "@mod/mfa-reading";
import { enrollmentWitnesses } from "@mod/mfa-witness";
import { witnessBackfill } from "./contract.ts";
import { backfillWith, witnessingWith } from "./witnessing.ts";

export default defineModule({ name: "mfa-witnessing" }, (m) => [
	m.contribute(witnessing).by(async (c) => {
		const [witness, ...more] = await c.collect(enrollmentWitnesses);
		if (!witness || more.length > 0) {
			return c.refuse("mfa-witnessing", "needs exactly one enrollment witness composed");
		}
		const token = () => Buffer.from(c.random.bytes(16)).toString("base64url");
		return witnessingWith({ witness, audit: await c.get(audit), log: c.log, token });
	}),
	m.provide(witnessBackfill).by(async (c) => {
		const [witness, ...more] = await c.collect(enrollmentWitnesses);
		if (!witness || more.length > 0) {
			return c.refuse("mfa-witnessing", "needs exactly one enrollment witness composed");
		}
		const decided = c.late(factorReading);
		const token = () => Buffer.from(c.random.bytes(16)).toString("base64url");
		return {
			settle: backfillWith({
				witness,
				// As written, a factor whose unique value is not claimed told apart from none.
				standing: (subject) => decided().writtenStanding(subject),
				token,
			}),
		};
	}),
]);
