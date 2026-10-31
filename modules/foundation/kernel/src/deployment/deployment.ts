import type { KernelSettings } from "../config/settings.ts";
import type { Module } from "../module.ts";
import { type Refusal, readThrown } from "../refusal/refusal.ts";

/**
 * A module's declaration, read and asked as its method once, inside the hold: its getter, its call
 * and every part of its answer `read` touches may throw, and none of what they throw is kept.
 */
function asked<T>(
	module: Module,
	name: "replicaSafe" | "refusedInProduction",
	section: unknown,
	read: {
		readonly value: (declared: unknown) => T | undefined;
		readonly answer: (answer: unknown) => T | undefined;
	},
	absent: T,
): T | undefined {
	return readThrown<T | undefined>(() => {
		const declared: unknown = module[name];
		if (declared === undefined) return absent;
		if (typeof declared !== "function") return read.value(declared);
		return read.answer(Reflect.apply(declared, module, [section]));
	}, undefined);
}

/** A boolean as it is, or none for any other answer. */
const readSafe = (answer: unknown) => (typeof answer === "boolean" ? answer : undefined);

/**
 * A list of key and reason strings, copied out of the answer by index (never by its iterator), or
 * none for anything else: a list's own items only, each a record of two non-empty strings.
 */
function readRefusals(answer: unknown): { key: string; reason: string }[] | undefined {
	if (!Array.isArray(answer)) return undefined;
	const read: { key: string; reason: string }[] = [];
	for (let i = 0; i < answer.length; i++) {
		const item: unknown = answer[i];
		if (item === null || typeof item !== "object") return undefined;
		const { key, reason } = item as { key?: unknown; reason?: unknown };
		if (typeof key !== "string" || typeof reason !== "string" || !key || !reason) return undefined;
		read.push({ key, reason });
	}
	return read;
}

/** On multiple instances, each module that declares itself unsafe there, or declares nothing of them. */
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
		const safe = asked<boolean | "unsaid">(
			module,
			"replicaSafe",
			sections.get(module),
			{ value: readSafe, answer: readSafe },
			"unsaid",
		);
		if (safe === "unsaid") {
			// The type requires the declaration; a module that has none got past it, as JavaScript.
			refusals.push({
				where: module.name,
				reason: "declares nothing about multiple instances: say replicaSafe",
			});
		} else if (safe === undefined) {
			refusals.push({ where: module.name, reason: "its multi-instance check failed" });
		} else if (!safe) {
			refusals.push({
				where: module.name,
				reason: "declares itself unsafe for multiple instances",
			});
		}
	}
}

/**
 * Each module's own refusals of what its section must not hold in production: refused there, and in
 * development answered, to be warned. A check that cannot be read refuses its module in either.
 */
export function checkProduction(
	modules: readonly Module[],
	sections: Map<Module, unknown>,
	environment: KernelSettings["environment"],
	refusals: Refusal[],
): readonly Refusal[] {
	const allowed: Refusal[] = [];
	for (const module of modules) {
		if (module.section !== undefined && !sections.has(module)) continue;
		// A function only: anything written in its place is no check.
		const read = asked(
			module,
			"refusedInProduction",
			sections.get(module),
			{ value: () => undefined, answer: readRefusals },
			[],
		);
		if (read === undefined) {
			refusals.push({ where: module.name, reason: "its production check failed" });
			continue;
		}
		const found = read.map(({ key, reason }) => ({ where: `${module.name}.${key}`, reason }));
		(environment === "production" ? refusals : allowed).push(...found);
	}
	return allowed;
}
