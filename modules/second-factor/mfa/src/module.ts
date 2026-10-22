import { audit } from "@mod/audit";
import { contract, defineModule } from "@mod/kernel";
import { amrSources } from "@mod/login-gates";
import { factorBinding } from "@mod/mfa-binding";
import { factorKinds, firstBindingGates, secondFactorAmr, witnessing } from "@mod/mfa-extensions";
import { factorManaging } from "@mod/mfa-managing";
import { factorReading } from "@mod/mfa-reading";
import { enrollmentWitnesses } from "@mod/mfa-witness";
import { resealers, seal } from "@mod/seal";
import { enforcers, factorStore, proofSteps } from "./contract.ts";
import { addsMfa, byKind, type Decisions, factorDecisions } from "./factors.ts";
import { resealerOver } from "./records/resealer.ts";
import { section } from "./section.ts";

/** mfa's decisions, built once in each app and provided as its three faces; never offered. */
const decisions = contract<Decisions>("mfa.decisions");

export default defineModule({ name: "mfa", section, replicaSafe: true }, (m) => [
	m.contribute(amrSources).by(async (c) => {
		const kinds = await c.collect(factorKinds);
		const second = kinds.some(addsMfa) ? [secondFactorAmr] : [];
		return { name: "mfa", amr: [...second, ...kinds.flatMap((k) => k.amr)] };
	}),
	m.provide(decisions).by(async (c) => {
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
		const stored = await c.get(factorStore);
		// A binding writes its factor and the claim on its value at once: never one without the other.
		if (typeof stored.updateTogether !== "function") {
			return c.refuse(
				"mfa",
				"its factor store cannot write a list and a claim as one (updateTogether)",
			);
		}
		return factorDecisions({
			stored,
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
	// The three faces are the one implementation, built once in each app.
	m.provide(factorReading).by((c) => c.get(decisions)),
	m.provide(factorBinding).by((c) => c.get(decisions)),
	m.provide(factorManaging).by((c) => c.get(decisions)),
	m
		.contribute(resealers)
		.by(async (c) => resealerOver(await c.get(factorStore), await c.get(seal))),
]);
