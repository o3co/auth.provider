import type { Guarantee, Mark, Method, Policy, Route } from "../contract.ts";

/** A route that breaks what it declares, and how. */
export interface Broken {
	readonly route: Route;
	readonly reason: string;
}

const reasonFor = { "own-site": "crossSite", "per-source": "unlimited" } as const;

/** The breaks of the routes against what each declares, a route that declares nothing included. */
export function brokenGuarantees(
	routes: readonly Route[],
	marks: readonly Mark[],
): readonly Broken[] {
	const marked = (guarantee: Guarantee, method: Method): ReadonlySet<Policy<unknown>> =>
		new Set(
			marks
				.filter((mark) => mark.guarantee === guarantee)
				.flatMap((mark) => mark.policies)
				.filter((entry) => entry.methods.includes(method))
				.map((entry) => entry.policy),
		);
	return routes.flatMap((route) => breaksOf(route, marked).map((reason) => ({ route, reason })));
}

function breaksOf(
	route: Route,
	marked: (guarantee: Guarantee, method: Method) => ReadonlySet<Policy<unknown>>,
): readonly string[] {
	const { method } = route;
	if (method === "GET" && route.changesState === undefined) {
		return ["a GET route says whether it changes state (changesState)"];
	}
	if (method !== "GET" && route.changesState === false) {
		return [`a ${method} route changes state; changesState: false is for a GET`];
	}
	const changes = method !== "GET" || route.changesState === true;
	const used = (route.uses ?? []).map((u) => u.policy);
	const at = (guarantee: Guarantee) => {
		const kept = marked(guarantee, method);
		return used.findIndex((p) => kept.has(p));
	};
	const breaks = (["own-site", "per-source"] as const).flatMap((guarantee) => {
		const field = reasonFor[guarantee];
		const reason = route[field];
		const kept = at(guarantee) >= 0;
		if (reason !== undefined && reason.trim() === "") return [`an empty reason in ${field}`];
		if (reason !== undefined && !changes)
			return [`a reason in ${field} on a route that changes no state`];
		if (!changes) return [];
		if (kept && reason !== undefined) {
			return [`both a policy marked ${guarantee} for ${method} and a reason in ${field}`];
		}
		if (!kept && reason === undefined) {
			return [
				`changes state with no policy marked ${guarantee} for ${method}, nor a reason in ${field}`,
			];
		}
		return [];
	});
	const ownSite = at("own-site");
	const perSource = at("per-source");
	if (ownSite >= 0 && perSource >= 0 && ownSite > perSource) {
		return [...breaks, "its own-site policy runs after its per-source policy"];
	}
	return breaks;
}
