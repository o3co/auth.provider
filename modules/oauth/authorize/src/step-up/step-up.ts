import { type Acr, acr } from "@mod/acr";
import type { BuildContext } from "@mod/kernel";
import { type Again, type Decision, refusal } from "../decision.ts";
import type { Reauth } from "../reauth/reauth.ts";
import type { Reauths } from "../reauth/reauths.ts";
import type { Settings } from "../section.ts";

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
/** A claims parameter is judged for acr, asked through acr_values, and an essential auth_time; the rest is ignored. */
function claimsAsked(text: string): "malformed" | "acr" | { readonly knownTime: boolean } {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return "malformed";
	}
	if (!isObject(parsed)) return "malformed";
	const asks = (part: unknown) => isObject(part) && Object.hasOwn(part, "acr");
	if (asks(parsed.id_token) || asks(parsed.userinfo)) return "acr";
	const authTime = isObject(parsed.id_token) ? parsed.id_token.auth_time : undefined;
	return { knownTime: isObject(authTime) && authTime.essential === true };
}

/** Where the request stands for raising its authentication. */
export interface Standing {
	readonly acrs: readonly string[];
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
	 * The acr asked that `acr` knows, in the asked order, and whether an essential `auth_time` asks for
	 * a known authentication time; a refusal when it knows none, or `claims` asks for acr.
	 */
	asked(
		one: (name: string) => string | undefined,
		params: ReadonlyMap<string, string>,
	):
		| { readonly kind: "asked"; readonly acrs: readonly string[]; readonly knownTime: boolean }
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
			const acrs = table.known(one("acr_values") ?? "");
			if (params.has("acr_values") && acrs.length === 0) {
				return refusal("unmet_authentication_requirements");
			}
			const claimsText = one("claims");
			const claims = claimsText === undefined ? { knownTime: false } : claimsAsked(claimsText);
			if (claims === "malformed") return refusal("invalid_request", "claims is not a JSON object");
			if (claims === "acr") return refusal("invalid_request", "request acr through acr_values");
			return { kind: "asked", acrs, knownTime: claims.knownTime };
		},
		async met({ acrs, amr, authenticatedAt, none, taken, params, again }) {
			// The first met in the order asked is the one the code carries.
			const met = table.met(acrs, amr);
			if (acrs.length === 0 || met !== undefined)
				return { kind: "met", ...(met !== undefined ? { acr: met } : {}) };
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

/** The step over `acr`'s table the assembly gives and the package's `step-up-page`. */
export const stepUpOver = async (c: BuildContext<Settings>, reauths: Reauths) =>
	stepUpWith({ acr: await c.get(acr), stepUpPage: c.section["step-up-page"], reauths });
