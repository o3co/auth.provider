import { deepFreeze } from "@mod/kernel";
import type { HttpRequest, HttpResponse, Policy, PolicyRule, Route } from "../contract.ts";

/** A route with its guard: the policies it uses, in its order; the first that answers ends the request. */
export type GuardedRoute = Route & {
	readonly guard?: (request: HttpRequest) => Promise<HttpResponse | "pass">;
};

/** Routes guarded by their policies, matched by value (never label), each with a frozen copy of what it uses; or a policy with no rule, or two. */
export function withPolicies(
	routes: readonly Route[],
	rules: readonly PolicyRule[],
):
	| { readonly kind: "applied"; readonly routes: readonly GuardedRoute[] }
	| { readonly kind: "missing"; readonly missing: readonly { route: Route; label: string }[] }
	| { readonly kind: "twice"; readonly label: string } {
	const ruleOf = new Map<Policy<unknown>, PolicyRule>(rules.map((rule) => [rule.policy, rule]));
	const twice = rules.find((rule, at) => rules.findIndex((r) => r.policy === rule.policy) !== at);
	if (twice) return { kind: "twice", label: twice.policy.label };
	const missing = routes.flatMap((route) =>
		(route.uses ?? [])
			.filter((use) => !ruleOf.has(use.policy))
			.map((use) => ({ route, label: use.policy.label })),
	);
	if (missing.length > 0) return { kind: "missing", missing };
	return {
		kind: "applied",
		routes: routes.map((route) => {
			const steps = Object.freeze(
				(route.uses ?? []).map((use) =>
					Object.freeze({
						rule: ruleOf.get(use.policy) as PolicyRule,
						options: deepFreeze(structuredClone(use.options)),
					}),
				),
			);
			if (steps.length === 0) return route;
			return Object.freeze({
				...route,
				guard: async (request: HttpRequest) => {
					for (const { rule, options } of steps) {
						const answer = await rule.apply(request, options);
						if (answer !== "pass") return answer;
					}
					return "pass" as const;
				},
			});
		}),
	};
}
