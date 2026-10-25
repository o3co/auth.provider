import type { Contract, ExtensionPoint, Handle } from "../handles.ts";
import type { Module } from "../module.ts";
import type { Refusal } from "../refusal/refusal.ts";

/** Why a contract refuses a module taking it, by its takenBy; none where it may. */
export function takenByRefusal(contract: Contract<unknown>, module: Module): string | undefined {
	const { takenBy } = contract;
	if (takenBy === undefined || takenBy.includes(module.name)) return undefined;
	return takenBy.length === 0
		? `${contract.label} is taken by no module`
		: `${contract.label} is taken by ${takenBy.join(", ")} alone`;
}

/** Why a point's rule refuses this many contributions; none where it holds. */
export function countRefusal(
	rule: { readonly multiplicity: string },
	count: number,
): string | undefined {
	if (rule.multiplicity === "one" && count !== 1) {
		return `needs exactly one contribution (${count})`;
	}
	if (rule.multiplicity === "some" && count === 0) return "needs at least one contribution";
	return undefined;
}

/**
 * Each module's takes, held against what the modules provide and contribute before anything is
 * built: a contract no other module provides, one its takenBy does not let it take, and a point
 * whose registered contributions (one that fails as it builds among them) break its rule, each
 * point once by identity. A function is asked only with a section that passed. Answers the takes
 * each declaring module is held to while it is built.
 */
export function checkTakes(
	modules: readonly Module[],
	sections: Map<Module, unknown>,
	parts: {
		readonly providers: ReadonlyMap<Contract<unknown>, unknown>;
		readonly contributions: ReadonlyMap<ExtensionPoint<unknown>, readonly unknown[]>;
	},
	refusals: Refusal[],
): Map<Module, ReadonlySet<Handle>> {
	const held = new Map<Module, ReadonlySet<Handle>>();
	const pointsChecked = new Set<Handle>();
	for (const module of modules) {
		const { takes } = module;
		if (takes === undefined) continue;
		const passed = module.section === undefined || sections.has(module);
		if (typeof takes === "function" && !passed) continue;
		const handles = new Set(typeof takes === "function" ? takes(sections.get(module)) : takes);
		held.set(module, handles);
		const own = new Set((module.provides ?? []).map((provision) => provision.contract));
		for (const handle of handles) {
			if (handle.kind === "contract") {
				const taken = takenByRefusal(handle, module);
				if (taken) refusals.push({ where: module.name, reason: taken });
				if (!own.has(handle) && !parts.providers.has(handle)) {
					refusals.push({ where: module.name, reason: `no module provides ${handle.label}` });
				}
			} else if (!pointsChecked.has(handle)) {
				pointsChecked.add(handle);
				const count = parts.contributions.get(handle as ExtensionPoint<unknown>)?.length ?? 0;
				const broken = countRefusal(handle.rule, count);
				if (broken) refusals.push({ where: handle.label, reason: broken });
			}
		}
	}
	return held;
}
