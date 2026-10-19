import { audit } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { amrSources } from "@mod/login-gates";
import { resealers, seal } from "@mod/seal";
import { entryRequirements, sessions } from "@mod/session";
import {
	factorKinds,
	factorStore,
	factors,
	firstBindingGates,
	proofSteps,
	secondFactorAmr,
} from "./contract.ts";
import {
	addsMfa,
	byKind,
	counting,
	factorDecisions,
	secondFactorAt,
	signedInAt,
} from "./factors.ts";
import { factorRecords } from "./records/records.ts";
import { resealerOver } from "./records/resealer.ts";
import { section } from "./section.ts";

const admit = { kind: "admit" } as const;
const short = (error: string) => ({ kind: "short", answer: { error } }) as const;

export default defineModule({ name: "mfa", section, replicaSafe: true }, (m) => [
	m.contribute(amrSources).by(async (c) => {
		const kinds = await c.collect(factorKinds);
		const second = kinds.some(addsMfa) ? [secondFactorAmr] : [];
		return { name: "mfa", amr: [...second, ...kinds.flatMap((k) => k.amr)] };
	}),
	m.provide(factors).by(async (c) => {
		const open = c.late(sessions);
		await c.collect(proofSteps);
		const kinds = await c.collect(factorKinds);
		if (c.section.mode === "required" && !kinds.some((k) => k.counts && addsMfa(k))) {
			return c.refuse("mfa.mode", "required needs a factor kind that counts and adds mfa");
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
			recent: (at) => open().recent(at),
			audit: await c.get(audit),
		});
	}),
	m
		.contribute(resealers)
		.by(async (c) => resealerOver(await c.get(factorStore), await c.get(seal))),
	m.contribute(entryRequirements).by(async (c) => {
		const records = factorRecords(await c.get(factorStore));
		const kinds = byKind(await c.collect(factorKinds));
		const required = c.section.mode === "required";
		const open = c.late(sessions);
		return {
			name: "mfa",
			// "use" only under "required"; credentials always.
			judges: ["use", "credentials"],
			admits: async (context, level) => {
				if (level === "use" && required && !context.amr.includes(secondFactorAmr)) {
					return short("mfa_required");
				}
				if (level !== "credentials") return admit;
				const proven = secondFactorAt(context);
				if (proven !== undefined && open().recent(proven)) return admit;
				// With no counting factor yet, a recent sign-in is the strongest proof there is.
				const none = counting(await records.list(context.subject), kinds).length === 0;
				const signedIn = signedInAt(context);
				if (none && signedIn !== undefined && open().recent(signedIn)) return admit;
				return short("step_up_required");
			},
		};
	}),
]);
