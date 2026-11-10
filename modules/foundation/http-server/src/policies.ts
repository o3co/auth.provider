import type { HttpRequest, HttpResponse, Method, Policy } from "@mod/http";
import { extensionPoint } from "@mod/kernel";

/** How a policy applies: pass the request on to the next, or answer it. Throws Unavailable when it cannot tell. */
export interface PolicyRule {
	readonly policy: Policy<unknown>;
	apply(
		request: HttpRequest,
		options: unknown,
	): "pass" | HttpResponse | Promise<"pass" | HttpResponse>;
}

export function applying<O>(
	policy: Policy<O>,
	apply: (
		request: HttpRequest,
		options: O,
	) => "pass" | HttpResponse | Promise<"pass" | HttpResponse>,
): PolicyRule {
	return { policy: policy as Policy<unknown>, apply: apply as PolicyRule["apply"] };
}

/** The rules of the policies, one per policy; the server matches them to the policies routes use by value. */
export const policies = extensionPoint<PolicyRule>("http-server.policies", {
	multiplicity: "many",
});

/** What a route's policies keep: `own-site`, no other site's request reaches the handler; `per-source`, a source over its count does not. */
export type Guarantee = "own-site" | "per-source";

/** A policy owner's own claim that these policies keep a guarantee, each for the methods named; a claim, never a proof. */
export interface Mark {
	readonly guarantee: Guarantee;
	readonly policies: readonly {
		readonly policy: Policy<unknown>;
		readonly methods: readonly Method[];
	}[];
}

/** One mark per guarantee, matched to the policies a route uses by value. */
export const marks = extensionPoint<Mark>("http-server.marks", {
	multiplicity: "keyed",
	keyOf: (mark) => mark.guarantee,
});
