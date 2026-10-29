import { ConfigError, fromMap } from "@o3co/ts.hocon";
import { getValidated } from "@o3co/ts.hocon/zod";
import { type ZodType, z } from "zod";
import { deepFreeze } from "../freeze.ts";
import type { Module } from "../module.ts";
import { type Refusal, readThrown } from "../refusal/refusal.ts";
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

/** What a section is refused with where its schema fails and tells no issue it can read. */
const schemaFailed: Issue = Object.freeze({ message: "its schema failed as it read the section" });

/** Checks a section with the HOCON library's typed reading: a string converts as the schema asks. */
function readSection<T>(
	schema: ZodType<T>,
	raw: unknown,
): { readonly value: T } | { readonly issues: readonly Issue[] } {
	try {
		const tree = fromMap({ raw: plainTree(raw, "raw") });
		return { value: getValidated(tree, "raw", schema) };
	} catch (error) {
		// Read through readThrown: a schema of a module's may throw any value, one whose reading throws too.
		const kind = readThrown(
			() =>
				error instanceof ConfigError
					? "configuration"
					: error instanceof z.core.$ZodError
						? "schema"
						: "other",
			"other",
		);
		if (kind === "configuration") {
			const path = readThrown(() => keysOf((error as ConfigError).path), []);
			return { issues: [{ message: "holds a value configuration cannot hold", path }] };
		}
		// A schema error's issues, where it holds a list of any; one holding none fails as any other throw.
		const issues =
			kind === "schema"
				? readThrown(() => {
						const told = (error as z.core.$ZodError).issues;
						return Array.isArray(told) && told.length > 0 ? told : undefined;
					}, undefined)
				: undefined;
		// Anything else the schema threw: refused by the module's name, its text never kept.
		return { issues: issues ?? [schemaFailed] };
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
): { kernel: KernelSettings; unsure: ReadonlySet<Unsure>; sections: Map<Module, unknown> } {
	const sections = new Map<Module, unknown>();
	if (!isPlainObject(config)) {
		refusals.push({ where: "config", reason: "the configuration root is not an object" });
		return { ...refusedKernel(undefined), sections };
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
			refusals.push({
				where: key,
				reason: "section for a module that is not loaded: take it out, or compose the module",
			});
		}
	}
	const { kernel, unsure } = readKernel(config[KERNEL_SECTION], refusals);
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
	return { kernel, unsure, sections };
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
		// An issue is the schema's, so read as a thrown value is: one of another shape is the schema's failure.
		const refusal = readThrown((): Refusal | undefined => {
			const keys = issue.path ?? [];
			if (!Array.isArray(keys) || typeof issue.message !== "string") return undefined;
			const path = keys.map(String).join(".");
			const notSet =
				issue.code !== undefined &&
				typeCodes.has(issue.code) &&
				absentAt(raw, keys) &&
				inZodsWords(issue);
			return {
				where: path ? `${name}.${path}` : name,
				reason: notSet ? "required, and not set" : issue.message,
			};
		}, undefined);
		refusals.push(refusal ?? { where: name, reason: schemaFailed.message });
	}
}

/** The kernel settings the deployment's checks read; one a refused section does not hold validly is unsure. */
export type Unsure = "deployment" | "environment";

function readKernel(
	raw: unknown,
	refusals: Refusal[],
): { kernel: KernelSettings; unsure: ReadonlySet<Unsure> } {
	const result = readSection(kernelSection, raw ?? null);
	if (!("issues" in result)) return { kernel: result.value, unsure: new Set() };
	refuseIssues(KERNEL_SECTION, result.issues, refusals, raw);
	return refusedKernel(raw);
}

/**
 * Stands in for a refused kernel section, boot being refused before any of it is used: it keeps the
 * deployment and environment the section holds validly, so their checks are asked as written, and
 * names the others unsure, whose checks are not asked.
 */
function refusedKernel(raw: unknown): { kernel: KernelSettings; unsure: ReadonlySet<Unsure> } {
	const written = isPlainObject(raw) ? raw : {};
	const unsure = new Set<Unsure>();
	const kept: Partial<Record<Unsure, unknown>> = {};
	for (const key of ["deployment", "environment"] as const) {
		const read = kernelSection.shape[key].safeParse(written[key]);
		if (read.success) kept[key] = read.data;
		else unsure.add(key);
	}
	return { kernel: kernelSection.parse({ deployment: "single", ...kept }), unsure };
}
