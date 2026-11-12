import { audit } from "@mod/audit";
import { erasers } from "@mod/erasure-extensions";
import { contract, defineModule } from "@mod/kernel";
import { amrSources } from "@mod/login-gates";
import { factorBinding } from "@mod/mfa-binding";
import { factorKinds, firstBindingGates, secondFactorAmr, witnessing } from "@mod/mfa-extensions";
import { factorManaging } from "@mod/mfa-managing";
import { factorReading } from "@mod/mfa-reading";
import { enrollmentWitnesses } from "@mod/mfa-witness";
import { resealers, seal } from "@mod/seal";
import { enforcers, factorStore, proofSteps } from "./contract.ts";
import { factorEraser } from "./erasure/eraser.ts";
import { addsMfa, byKind, type Decisions, factorDecisions, leftOut } from "./factors.ts";
import { portsRefused } from "./records/ports.ts";
import { resealerOver } from "./records/resealer.ts";
import { section } from "./section.ts";

/** mfa's decisions, built once in each app and provided as its three faces; never offered. */
const decisions = contract<Decisions>("mfa.decisions");

export default defineModule(
	{
		name: "mfa",
		section,
		replicaSafe: true,
		takes: [
			audit,
			enrollmentWitnesses,
			enforcers,
			factorKinds,
			factorStore,
			firstBindingGates,
			proofSteps,
			witnessing,
			seal,
		],
	},
	(m) => [
		m.contribute(amrSources).by(async (c) => {
			const required = c.section.mode === "required";
			const kinds = (await c.collect(factorKinds)).filter((k) => !leftOut(k, required));
			const second = kinds.some(addsMfa) ? [secondFactorAmr] : [];
			return { name: "mfa", amr: [...second, ...kinds.flatMap((k) => k.amr)] };
		}),
		m.provide(decisions).by(async (c) => {
			await c.collect(proofSteps);
			const required = c.section.mode === "required";
			const composed = await c.collect(factorKinds);
			if (required && !composed.some((k) => k.counts)) {
				return c.refuse("mfa.mode", "required needs a factor kind that counts");
			}
			// The operator's choice, yet said at every start: a session is used with no second factor.
			if (c.section.mode !== "required") {
				c.log.warn("mfa.not_required", { reason: "using a session needs no second factor" });
			}
			// The kinds taken: under required, one whose proof adds no mfa would let a login prove
			// nothing a session may use, so it is left out, and every lookup by kind answers as for a
			// kind not composed. Said at every start, from the same judgment, rather than refused.
			const taken = composed.filter((k) => !leftOut(k, required));
			for (const k of composed.filter((k) => leftOut(k, required))) {
				c.log.warn("mfa.kind_not_taken", { kind: k.kind });
			}
			// Sessions are held to the factors elsewhere: without that module, using them would ask for none.
			if ((await c.collect(enforcers)).length === 0) {
				return c.refuse(
					"mfa",
					"mfa needs a module holding sessions to its factors; compose mfa-entry",
				);
			}
			const [contributed, ...others] = await c.collect(witnessing);
			const witnesses = await c.collect(enrollmentWitnesses);
			if (others.length > 0) return c.refuse("mfa", "more than one witnessing is contributed");
			// A witness nothing asks would leave a lost store to read as never enrolled: never silently.
			if (!contributed && witnesses.length > 0) {
				return c.refuse("mfa", "an enrollment witness is composed without mfa-witnessing");
			}
			const stored = await c.get(factorStore);
			// A binding writes its factor and the claim on its value at once: never one without the other.
			const parted = portsRefused(stored);
			if (parted !== undefined) return c.refuse("mfa", parted);
			return factorDecisions({
				stored,
				kinds: byKind(taken),
				seal: await c.get(seal),
				required,
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
		// Its build takes only the factor store, collecting no probes: the erasure gate collects erasers.
		m.contribute(erasers).by(async (c) => factorEraser(await c.get(factorStore))),
		m
			.contribute(resealers)
			.by(async (c) => resealerOver(await c.get(factorStore), await c.get(seal))),
	],
);
