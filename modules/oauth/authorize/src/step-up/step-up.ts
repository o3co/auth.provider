import { type Acr, acr } from "@mod/acr";
import type { BuildContext } from "@mod/kernel";
import type { Reauth, Reauths } from "@mod/reauth";
import { claimsAsked } from "../claims-request/claims-request.ts";
import { type Again, type Decision, refusal } from "../decision.ts";
import type { Settings } from "../section.ts";

/** Where the request stands for raising its authentication. */
export interface Standing {
	readonly acrs: readonly string[];
	/** Whether an acr was asked at all: one asked voluntarily and not met gives the session's current acr. */
	readonly wanted: boolean;
	/** Whether the acr was asked as essential, so one not met is refused rather than passed over. */
	readonly essential: boolean;
	readonly amr: readonly string[];
	readonly authenticatedAt: number;
	/** Whether `prompt=none` was asked. */
	readonly none: boolean;
	readonly taken: Reauth | undefined;
	readonly params: ReadonlyMap<string, string>;
	readonly again: Again;
}

export interface StepUp {
	/**
	 * The acr asked that `acr` knows, in the asked order, whether they are essential, and whether an
	 * essential `auth_time` asks for a known authentication time; a refusal for a malformed `claims`,
	 * or an essential acr `acr` knows none of.
	 */
	asked(
		one: (name: string) => string | undefined,
		params: ReadonlyMap<string, string>,
	):
		| {
				readonly kind: "asked";
				readonly acrs: readonly string[];
				readonly wanted: boolean;
				readonly essential: boolean;
				readonly knownTime: boolean;
		  }
		| Decision;
	/** The acr the code carries, or a refusal, or the step-up page. */
	met(standing: Standing): Promise<{ readonly kind: "met"; readonly acr?: string } | Decision>;
}

export interface StepUpParts {
	readonly acr: Acr;
	/** The package's `step-up-page`, when set. */
	readonly stepUpPage: string | undefined;
	readonly reauths: Reauths;
}

export function stepUpWith({ acr: table, stepUpPage, reauths }: StepUpParts): StepUp {
	return {
		asked(one, params) {
			const claimsText = one("claims");
			const claims =
				claimsText === undefined ? { knownTime: false, acr: [] } : claimsAsked(claimsText);
			if (claims === "malformed") return refusal("invalid_request", "claims is not a JSON object");
			const { knownTime } = claims;
			// A claims value is one acr as written: known only where the table holds it whole.
			const known = (value: string) => {
				const named = table.known(value);
				return named.length === 1 && named[0] === value;
			};
			const essentials = claims.acr.filter((asked) => asked.essential && asked.values.length > 0);
			const [first, ...others] = essentials;
			if (first !== undefined) {
				// The acr carried meets every essential request: those all of them name, in the first's order.
				const acrs = first.values.filter(
					(value) => known(value) && others.every((other) => other.values.includes(value)),
				);
				if (acrs.length === 0) return refusal("unmet_authentication_requirements");
				return { kind: "asked", acrs, wanted: true, essential: true, knownTime };
			}
			// Voluntary: the claims parameter's acr values stand in for acr_values, which ask the same.
			const values = claims.acr.flatMap((asked) => asked.values);
			const acrs = values.length > 0 ? values.filter(known) : table.known(one("acr_values") ?? "");
			const wanted = claims.acr.length > 0 || params.has("acr_values");
			return { kind: "asked", acrs, wanted, essential: false, knownTime };
		},
		async met({ acrs, wanted, essential, amr, authenticatedAt, none, taken, params, again }) {
			// The first met in the order asked is the one the code carries.
			const met = table.met(acrs, amr);
			if (met !== undefined) return { kind: "met", acr: met };
			// Asked voluntarily and not met, the session's current acr instead (Core §5.5.1.1); none asked, none.
			const current = () => {
				const acr = wanted ? table.current(amr) : undefined;
				return { kind: "met" as const, ...(acr !== undefined ? { acr } : {}) };
			};
			if (acrs.length === 0) return current();
			// Asked voluntarily (Core §3.1.2.1), one not met is passed over where raising cannot, or did not, meet it.
			const raises = stepUpPage !== undefined && !taken?.stepUp && !none;
			if (!essential && !raises) return current();
			if (none) return refusal("interaction_required");
			if (!stepUpPage || taken?.stepUp) return refusal("unmet_authentication_requirements");
			// The way back carries a newer login already proved, since raising keeps its time.
			const trip = await reauths.remember(params, taken?.at ?? authenticatedAt, true);
			const page = new URL(stepUpPage);
			page.searchParams.set("acr_values", acrs.join(" "));
			page.searchParams.set("redirect_to", again(["reauth"], [["reauth", trip]]));
			return { kind: "send", to: page.href };
		},
	};
}

/** What `stepUpOver` takes. */
export const stepUpTakes = [acr];

/** The step over `acr`'s table the assembly gives and the package's `step-up-page`. */
export const stepUpOver = async (c: BuildContext<Settings>, reauths: Reauths) =>
	stepUpWith({ acr: await c.get(acr), stepUpPage: c.section["step-up-page"], reauths });
