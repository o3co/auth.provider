import { audit } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { amrSources } from "@mod/login-gates";
import { factorKinds, firstBindingGates, secondFactorAmr, witnessing } from "@mod/mfa-extensions";
import { enrollmentWitnesses } from "@mod/mfa-witness";
import { resealers, seal } from "@mod/seal";
import { enforcers, factorStore, factors, proofSteps } from "./contract.ts";
import { addsMfa, byKind, factorDecisions } from "./factors.ts";
import { resealerOver } from "./records/resealer.ts";
import { section } from "./section.ts";

export default defineModule({ name: "mfa", section, replicaSafe: true }, (m) => [
	m.contribute(amrSources).by(async (c) => {
		const kinds = await c.collect(factorKinds);
		const second = kinds.some(addsMfa) ? [secondFactorAmr] : [];
		return { name: "mfa", amr: [...second, ...kinds.flatMap((k) => k.amr)] };
	}),
	m.provide(factors).by(async (c) => {
		await c.collect(proofSteps);
		const kinds = await c.collect(factorKinds);
		if (c.section.mode === "required" && !kinds.some((k) => k.counts)) {
			return c.refuse("mfa.mode", "required needs a factor kind that counts");
		}
		// Sessions are held to the factors elsewhere: without that module, using them would ask for none.
		if ((await c.collect(enforcers)).length === 0) {
			return c.refuse(
				"mfa",
				"mfa needs a module holding sessions to its factors; compose mfa-entry",
			);
		}
		const [contributed, ...others] = await c.collect(witnessing);
		if (others.length > 0) return c.refuse("mfa", "more than one witnessing is contributed");
		// A witness nothing asks would leave a lost store to read as never enrolled: never silently.
		if (!contributed && (await c.collect(enrollmentWitnesses)).length > 0) {
			return c.refuse("mfa", "an enrollment witness is composed without mfa-witnessing");
		}
		return factorDecisions({
			stored: await c.get(factorStore),
			kinds: byKind(kinds),
			seal: await c.get(seal),
			required: c.section.mode === "required",
			maxFactors: c.section["max-factors"],
			gates: await c.collect(firstBindingGates),
			random: c.random.bytes,
			now: c.clock.now,
			audit: await c.get(audit),
			witnessing: contributed,
			log: c.log,
		});
	}),
	m
		.contribute(resealers)
		.by(async (c) => resealerOver(await c.get(factorStore), await c.get(seal))),
]);
