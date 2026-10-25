import type { KernelSettings } from "../config/settings.ts";
import type { Module } from "../module.ts";
import { type Refusal, readThrown } from "../refusal/refusal.ts";

/** On multiple instances, each module that declares itself unsafe there. */
export function checkReplicas(
	modules: readonly Module[],
	sections: Map<Module, unknown>,
	deployment: KernelSettings["deployment"],
	refusals: Refusal[],
): void {
	if (deployment !== "multi") return;
	for (const module of modules) {
		// A section that failed its schema is refused already; the declaration expects a checked one.
		if (module.section !== undefined && !sections.has(module)) continue;
		const { replicaSafe } = module;
		// A function's throw is its module's refusal, its text never kept; the others are still asked.
		const safe =
			typeof replicaSafe === "function"
				? readThrown<boolean | undefined>(() => replicaSafe(sections.get(module)), undefined)
				: (replicaSafe ?? true);
		if (safe === undefined) {
			refusals.push({ where: module.name, reason: "its multi-instance check failed" });
		} else if (!safe) {
			refusals.push({
				where: module.name,
				reason: "declares itself unsafe for multiple instances",
			});
		}
	}
}

/** In production, each module's own refusals of what its section must not hold there. */
export function checkProduction(
	modules: readonly Module[],
	sections: Map<Module, unknown>,
	environment: KernelSettings["environment"],
	refusals: Refusal[],
): void {
	if (environment !== "production") return;
	for (const module of modules) {
		const { refusedInProduction } = module;
		if (refusedInProduction === undefined) continue;
		if (module.section !== undefined && !sections.has(module)) continue;
		// Read once, into plain strings: a throw, or an answer whose reading throws, is the module's
		// refusal with a fixed reason, never the thrown value, which may hold a secret.
		const read = readThrown<{ key: string; reason: string }[] | undefined>(
			() =>
				[...refusedInProduction(sections.get(module))].map(({ key, reason }) => ({
					key: String(key),
					reason: String(reason),
				})),
			undefined,
		);
		if (read === undefined) {
			refusals.push({ where: module.name, reason: "its production check failed" });
			continue;
		}
		for (const { key, reason } of read) refusals.push({ where: `${module.name}.${key}`, reason });
	}
}
