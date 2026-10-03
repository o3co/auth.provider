/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The check that a module refuses an unknown key inside its own section, at
 * every object level: a typo, or a key an older version read, then refuses
 * boot naming its path instead of being dropped or kept unread. Each level of
 * a valid sample of the section is given one unknown key, carrying a string
 * (what an environment variable sets) and then an empty object (what a
 * nested block sets), and parsed with the section's schema; a level where
 * either parses is named. A level whose keys are open by design — a record
 * keyed by names the deployment chooses — is exempted by the caller, with
 * its reason.
 *
 * Limits: only the levels the sample holds are reached, so a sample sets each
 * nested object, and an entry in each record and list, it should check; a
 * level that refuses both values for another reason (a record whose entries
 * refuse a string and an empty object) counts as refusing the key.
 */

import type { SectionSchema } from "../modules/manifest/module-section.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";

export interface SectionStrictnessOptions {
	/**
	 * The configuration each section's sample is read from, at the section's
	 * path: a resolved configuration, or a package's `reference.conf`, as
	 * plain data. A section it does not hold is sampled as `{}`.
	 */
	readonly tree?: unknown;
	/** A sample per module name, taken over what `tree` holds for its section. */
	readonly samples?: Readonly<Record<string, unknown>>;
	/**
	 * The levels whose keys are open by design, each an operator path
	 * (`<section>.<path>`, `*` matching any one key) mapped to why. An
	 * exemption inside a checked section that matches no level keeping an
	 * unknown key is itself a problem, so the list only shrinks.
	 */
	readonly exempt?: Readonly<Record<string, string>>;
}

/** The key no section declares. */
const UNKNOWN_KEY = "unknownKeyOfTheStrictnessCheck";

/** What an unknown key may carry: an environment variable's string, a nested block. */
const UNKNOWN_VALUES: readonly (() => unknown)[] = [() => "unknown", () => ({})];

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** The value at `segments` in `tree`, or `undefined`. */
function valueAt(tree: unknown, segments: readonly string[]): unknown {
	let cursor: unknown = tree;
	for (const segment of segments) {
		if (!isPlainObject(cursor) || !Object.hasOwn(cursor, segment)) return undefined;
		cursor = cursor[segment];
	}
	return cursor;
}

/** The path of every plain object in `value`, itself first; a list's elements by index. */
function objectLevels(value: unknown, at: readonly string[] = []): string[][] {
	if (Array.isArray(value)) {
		return value.flatMap((element, index) => objectLevels(element, [...at, String(index)]));
	}
	if (!isPlainObject(value)) return [];
	return [
		[...at],
		...Object.entries(value).flatMap(([key, child]) => objectLevels(child, [...at, key])),
	];
}

/** `value` with the unknown key set to `injected` in the object at `at`, copied along the way. */
function withUnknownKey(value: unknown, at: readonly string[], injected: unknown): unknown {
	if (at.length === 0) return { ...(value as Record<string, unknown>), [UNKNOWN_KEY]: injected };
	const [head, ...rest] = at as [string, ...string[]];
	if (Array.isArray(value)) {
		const copy = [...value];
		copy[Number(head)] = withUnknownKey(value[Number(head)], rest, injected);
		return copy;
	}
	const object = value as Record<string, unknown>;
	return { ...object, [head]: withUnknownKey(object[head], rest, injected) };
}

/** `undefined` when `schema` accepts `value`; otherwise why it does not. */
function refusal(schema: SectionSchema, value: unknown): string | undefined {
	try {
		const parsed = schema.safeParse(value);
		if (parsed.success) return undefined;
		return parsed.error.issues
			.map((issue) => `${issue.path.map(String).join(".") || "(section)"}: ${issue.message}`)
			.join("; ");
	} catch {
		// Boot parses a section synchronously; a schema that throws instead of
		// answering (an async refinement) refuses it there too.
		return "the schema threw instead of answering synchronously";
	}
}

/** Whether the exempt path `pattern` names the level at `segments`. */
function matches(pattern: string, segments: readonly string[]): boolean {
	const parts = pattern.split(".");
	return (
		parts.length === segments.length &&
		parts.every((part, index) => part === "*" || part === segments[index])
	);
}

/** Whether the exempt path `pattern` lies at or under the section at `section`. */
function inside(pattern: string, section: readonly string[]): boolean {
	const parts = pattern.split(".");
	return (
		parts.length >= section.length &&
		section.every((segment, index) => parts[index] === "*" || parts[index] === segment)
	);
}

/**
 * Every object level of the modules' sections where an unknown key is not
 * refused, as `<section>.<path>: …`, one line per problem, sorted — `[]` when
 * nothing is. Also named: a section whose sample its schema refuses (or
 * cannot parse synchronously), an exemption with no reason, and an exemption
 * inside a checked section that matches no level keeping an unknown key. A
 * module without a section is skipped; an exemption outside every checked
 * section is left to the check that holds its module.
 */
export function sectionStrictnessProblems(
	modules: readonly Module[],
	options: SectionStrictnessOptions = {},
): string[] {
	const exempt = Object.entries(options.exempt ?? {});
	const samples = options.samples ?? {};
	const problems: string[] = [];
	const used = new Set<string>();
	const checked: { readonly module: Module; readonly segments: readonly string[] }[] = [];
	for (const [path, reason] of exempt) {
		if (reason.trim() === "") problems.push(`${path}: exempt with no reason`);
	}
	for (const module of modules) {
		const section = module.section;
		if (section === undefined) continue;
		// Unset, `at` is the module's name as one key, not split on dots.
		const segments = section.at === undefined ? [module.name] : section.at.split(".");
		checked.push({ module, segments });
		const sample = Object.hasOwn(samples, module.name)
			? samples[module.name]
			: (valueAt(options.tree, segments) ?? {});
		const refused = refusal(section.schema, sample);
		if (refused !== undefined) {
			problems.push(
				`${segments.join(".")}: module "${module.name}"'s sample is refused by its section schema — ${refused}`,
			);
			continue;
		}
		for (const at of objectLevels(sample)) {
			const level = [...segments, ...at];
			const keeps = UNKNOWN_VALUES.some(
				(value) => refusal(section.schema, withUnknownKey(sample, at, value())) === undefined,
			);
			const exemptions = exempt.filter(([pattern]) => matches(pattern, level));
			if (exemptions.length > 0) {
				if (keeps) for (const [pattern] of exemptions) used.add(pattern);
				continue;
			}
			if (keeps) {
				problems.push(
					`${level.join(".")}: module "${module.name}"'s section schema does not refuse an unknown key`,
				);
			}
		}
	}
	for (const [pattern] of exempt) {
		if (used.has(pattern)) continue;
		const owner = checked.find(({ segments }) => inside(pattern, segments));
		if (owner === undefined) continue;
		problems.push(
			`${pattern}: exempt, but no level of module "${owner.module.name}"'s section it matches keeps an unknown key`,
		);
	}
	return problems.sort();
}
