import { audit } from "@mod/audit";
import { defineModule } from "@mod/kernel";
import { amrSources } from "@mod/login-gates";
import { resealers, seal } from "@mod/seal";
import { type AuthContext, entryRequirements } from "@mod/session";
import {
	factorKinds,
	factorStore,
	factors,
	firstBindingGates,
	proofSteps,
	secondFactorAmr,
} from "./contract.ts";
import { addsMfa, byKind, counting, factorDecisions } from "./factors.ts";
import { factorRecords } from "./records.ts";
import { resealerOver } from "./resealer.ts";
import { section } from "./section.ts";

const admit = { kind: "admit" } as const;
const short = (error: string) => ({ kind: "short", answer: { error } }) as const;
/** When the sign-in was, where it is known: a time the upstream did not give is never recent. */
const signedInAt = (context: AuthContext) =>
	context.authenticatedAtUnknown ? undefined : context.authenticatedAt;
/** When a second factor was last proven: a raise that added one, else a login that did; any other raise says nothing of one. */
const secondFactorAt = (context: AuthContext) => {
	const raised = context.raisedAmr?.includes(secondFactorAmr) ? context.raisedAt : undefined;
	if (raised !== undefined) return raised;
	return context.amr.includes(secondFactorAmr) ? signedInAt(context) : undefined;
};

export default defineModule({ name: "mfa", section, replicaSafe: true }, (m) => [
	m.contribute(amrSources).by(async (c) => {
		const kinds = await c.collect(factorKinds);
		const second = kinds.some(addsMfa) ? [secondFactorAmr] : [];
		return { name: "mfa", amr: [...second, ...kinds.flatMap((k) => k.amr)] };
	}),
	m.provide(factors).by(async (c) => {
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
			recentMs: c.section["manage-within"] * 1000,
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
		const recentMs = c.section["manage-within"] * 1000;
		return {
			name: "mfa",
			// "use" only under "required"; credentials always.
			judges: ["use", "credentials"],
			admits: async (context, level) => {
				if (level === "use" && required && !context.amr.includes(secondFactorAmr)) {
					return short("mfa_required");
				}
				if (level !== "credentials") return admit;
				const now = c.clock.now();
				const proven = secondFactorAt(context);
				if (proven !== undefined && now - proven <= recentMs) return admit;
				// With no counting factor yet, a recent sign-in is the strongest proof there is.
				const none = counting(await records.list(context.subject), kinds).length === 0;
				const signedIn = signedInAt(context);
				if (none && signedIn !== undefined && now - signedIn <= recentMs) return admit;
				return short("step_up_required");
			},
		};
	}),
]);
