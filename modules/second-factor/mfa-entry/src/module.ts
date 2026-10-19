import { defineModule } from "@mod/kernel";
import { enforcers, factors } from "@mod/mfa";
import { factorKinds, secondFactorAmr } from "@mod/mfa-extensions";
import { type AuthContext, sessions } from "@mod/session";
import { entryRequirements } from "@mod/session-requirements";
import { secondFactors } from "./contract.ts";

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

export default defineModule({ name: "mfa-entry" }, (m) => [
	m.contribute(enforcers).by(() => ({ name: "mfa-entry" })),
	m.provide(secondFactors).by((c) => {
		const open = c.late(sessions);
		return {
			provenRecently: (context) => {
				const at = secondFactorAt(context);
				return at !== undefined && open().recent(at);
			},
		};
	}),
	m.contribute(entryRequirements).by(async (c) => {
		const decided = await c.get(factors);
		const required = decided.secondFactorRequired();
		if (required && !(await c.collect(factorKinds)).some((k) => k.counts && k.addsSecondFactor)) {
			return c.refuse("mfa.mode", "required needs a kind that counts to add mfa");
		}
		const open = c.late(sessions);
		return {
			// mfa's name: answers and records outside name the requirement by it.
			name: "mfa",
			judges: ["use", "credentials"],
			admits: async (context, level) => {
				if (level === "use" && required && !context.amr.includes(secondFactorAmr)) {
					return short("mfa_required");
				}
				if (level !== "credentials") return admit;
				// Asked first, every time: a subject the witness marks while holding none stops here.
				const holds = await decided.countingHeld(context.subject, "credentials");
				const proven = secondFactorAt(context);
				if (proven !== undefined && open().recent(proven)) return admit;
				// With no counting factor yet, a recent sign-in is the strongest proof there is.
				const signedIn = signedInAt(context);
				if (signedIn === undefined || !open().recent(signedIn)) return short("step_up_required");
				return holds ? short("step_up_required") : admit;
			},
		};
	}),
]);
