import { ConfigError, fromMap } from "@o3co/ts.hocon";
import { getValidated } from "@o3co/ts.hocon/zod";
import { type ZodType, z } from "zod";
import { deepFreeze } from "../freeze.ts";
import type { Module } from "../module.ts";
import type { Refusal } from "../refusal.ts";
import { type KernelSettings, kernelSection } from "./settings.ts";

export const KERNEL_SECTION = "kernel";

/** The kernel's own section, a single deployment unless `settings` say otherwise; with none, all a new project needs. */
export function kernelConfig(settings: Partial<z.input<typeof kernelSection>> = {}) {
	return { [KERNEL_SECTION]: { deployment: "single", ...settings } };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
	const proto = Object.getPrototypeOf(value);
	return proto === null || proto === Object.prototype;
}

/** Why a value read as a section is read does not hold: zod's issue, or one configuration cannot hold. */
export type Issue = {
	readonly message: string;
	readonly path?: readonly PropertyKey[];
	readonly code?: string;
};

/** The codes zod gives a value of the wrong type or option, which is also what it says of none at all. */
const typeCodes = new Set(["invalid_type", "invalid_value", "invalid_union"]);
const zodWords = z.locales.en().localeError;
/** Whether the issue's message is zod's own words, not ones the schema's author wrote. */
const inZodsWords = (issue: Issue) => {
	const own = zodWords(issue as unknown as Parameters<typeof zodWords>[0]);
	return issue.message === (typeof own === "string" ? own : own?.message);
};

/** Whether the configuration holds nothing at `path` under `raw`, reading own keys alone. */
function absentAt(raw: unknown, path: readonly PropertyKey[]): boolean {
	let at = raw;
	for (const key of path) {
		if (at === null || typeof at !== "object" || !Object.hasOwn(at, key)) return true;
		at = (at as Record<PropertyKey, unknown>)[key];
	}
	return at === undefined;
}

/** Checks a section with the HOCON library's typed reading: a string converts as the schema asks. */
function readSection<T>(
	schema: ZodType<T>,
	raw: unknown,
): { readonly value: T } | { readonly issues: readonly Issue[] } {
	try {
		const tree = fromMap({ raw: plainTree(raw, "raw") });
		return { value: getValidated(tree, "raw", schema) };
	} catch (error) {
		if (error instanceof ConfigError) {
			return {
				issues: [{ message: "holds a value configuration cannot hold", path: keysOf(error.path) }],
			};
		}
		if (error instanceof z.core.$ZodError) return { issues: error.issues };
		throw error;
	}
}

/**
 * Reads `raw` against `schema` as a section is read, for a value a section passes through to a
 * schema of its own: a string converts as the schema asks; the value, or why it does not hold.
 */
export const readConfigured = readSection;

/** The value as HOCON holds it (undefined fields absent, only plain objects nested), `at` its path as `raw.a[0].b`. */
function plainTree(value: unknown, at: string): unknown {
	if (Array.isArray(value)) return value.map((item, i) => plainTree(item, `${at}[${i}]`));
	if (value === null || typeof value !== "object") return value;
	if (!isPlainObject(value)) throw new ConfigError("not a plain object", at);
	const fields = Object.entries(value).filter((entry) => entry[1] !== undefined);
	return Object.fromEntries(fields.map(([key, field]) => [key, plainTree(field, `${at}.${key}`)]));
}

/** A path as the HOCON library writes one under the section's `raw`, as the keys a refusal names. */
const keysOf = (path: string): string[] =>
	path
		.replace(/\[(\d+)\]/g, ".$1")
		.split(".")
		.slice(1);

export function readSections(
	modules: readonly Module[],
	config: unknown,
	refusals: Refusal[],
): { kernel: KernelSettings; sections: Map<Module, unknown> } {
	const sections = new Map<Module, unknown>();
	if (!isPlainObject(config)) {
		refusals.push({ where: "config", reason: "the configuration root is not an object" });
		return { kernel: refusedKernel(), sections };
	}
	const names = new Set<string>();
	for (const module of modules) {
		// "kernel" is taken by the kernel's own section.
		if (names.has(module.name) || module.name === KERNEL_SECTION) {
			refusals.push({ where: module.name, reason: "duplicate module name" });
		}
		names.add(module.name);
	}
	for (const key of Object.keys(config)) {
		if (key !== KERNEL_SECTION && !names.has(key)) {
			refusals.push({ where: key, reason: "section for a module that is not loaded" });
		}
	}
	const kernel = readKernel(config[KERNEL_SECTION], refusals);
	for (const module of modules) {
		const raw = Object.hasOwn(config, module.name) ? config[module.name] : undefined;
		if (module.section === undefined) {
			if (raw !== undefined)
				refusals.push({ where: module.name, reason: "module without a section" });
			continue;
		}
		const result = readSection(module.section, raw ?? {});
		if ("issues" in result) refuseIssues(module.name, result.issues, refusals, raw);
		else sections.set(module, deepFreeze(result.value));
	}
	return { kernel, sections };
}

/**
 * Each issue as a refusal by its key path. A key the configuration does not set, which the schema
 * needs a value of, is said to be required, unless the schema's author wrote its own words for it;
 * any other issue keeps the schema's words.
 */
function refuseIssues(
	name: string,
	issues: readonly Issue[],
	refusals: Refusal[],
	raw: unknown,
): void {
	for (const issue of issues) {
		const keys = issue.path ?? [];
		const path = keys.map(String).join(".");
		const notSet =
			issue.code !== undefined &&
			typeCodes.has(issue.code) &&
			absentAt(raw, keys) &&
			inZodsWords(issue);
		refusals.push({
			where: path ? `${name}.${path}` : name,
			reason: notSet ? "required, and not set" : issue.message,
		});
	}
}

function readKernel(raw: unknown, refusals: Refusal[]): KernelSettings {
	const result = readSection(kernelSection, raw ?? null);
	if (!("issues" in result)) return result.value;
	refuseIssues(KERNEL_SECTION, result.issues, refusals, raw);
	return refusedKernel();
}

/** Stands in for a refused kernel section: boot is refused before any of it is used. */
function refusedKernel(): KernelSettings {
	return kernelSection.parse({ deployment: "single" });
}
