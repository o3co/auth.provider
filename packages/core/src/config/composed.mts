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
 * The configuration as boot's one composed parse reads it, while core's
 * schema still mirrors sections other packages own. A composition root hands
 * `createApp` the configuration it resolved (the HOCON it layered, never
 * parsed first), and boot parses it once:
 *
 * 1. with the transitional base, {@link TransitionalConfigSchema}: core's own
 *    sections, and every section core's schema mirrors for a package, each
 *    optional;
 * 2. laid over what was written ({@link overlayConfig}), so a key no schema
 *    declares is kept, not stripped;
 * 3. then by the modules' own `configSchema`s, and by each module's section
 *    schema at its path, which boot writes back there.
 *
 * {@link readTransitionalConfig} is steps 1 and 2 alone, over the paths a
 * composition root reads before it knows its modules. Both are transitional:
 * they go once core mirrors no section and the composition root reads only
 * its own section first.
 */

import type { z } from "zod";
import { type AppConfig, CoreConfigSchema, fullSectionsSchema } from "./application.schema.mjs";
import { pickConfigSchema } from "./schema-path.mjs";

/**
 * The transitional base of boot's one composed parse: core's own sections,
 * required, and every section `fullSectionsSchema` mirrors for another
 * package's module, made optional. Each keeps its coercions and checks (a
 * `${?VAR}` string read as a number or a boolean, a value outside its
 * vocabulary refused), so a mirrored section is validated whenever a
 * configuration carries it, loaded module or not.
 */
export const TransitionalConfigSchema = CoreConfigSchema.extend(fullSectionsSchema.partial().shape);

/**
 * An object literal's kind of object: its prototype is `Object.prototype`, or
 * it has none. Configuration is merged, copied and written only through
 * these; anything else — a list, a `URL`, an instance a transform built — is
 * a value, taken whole.
 */
export function isPlainConfigObject(value: unknown): value is Record<string, unknown> {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
	const prototype: unknown = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

/**
 * `over` (a schema's parse) laid on `under` (what was written), key by key
 * through plain objects (`isPlainConfigObject`):
 *
 * - where both hold a plain object, their keys are merged the same way;
 * - anywhere else the parsed value wins whole (a list, a `URL`, a value whose
 *   type the schema changed);
 * - a key the parse holds as `undefined` is removed: the schema made nothing
 *   of the value written there (an empty environment variable read as unset);
 * - a key the parse does not hold is kept as written, which is how a key no
 *   schema declares survives the parse.
 *
 * An `undefined` `over` answers `under`. Neither input is changed: every
 * object on a merged path is a new one, and a value only one side holds is
 * that side's own.
 */
export function overlayConfig(under: unknown, over: unknown): unknown {
	if (over === undefined) return under;
	if (!isPlainConfigObject(under) || !isPlainConfigObject(over)) return over;
	const merged: Record<string, unknown> = {};
	for (const key of Object.keys(under)) defineConfigKey(merged, key, under[key]);
	for (const key of Object.keys(over)) {
		const value = over[key];
		if (value === undefined) {
			delete merged[key];
			continue;
		}
		defineConfigKey(
			merged,
			key,
			Object.hasOwn(under, key) ? overlayConfig(under[key], value) : value,
		);
	}
	return merged;
}

/** `target[key] = value`, defined rather than assigned: a key named `__proto__` stays a key. */
export function defineConfigKey(
	target: Record<string, unknown>,
	key: string,
	value: unknown,
): void {
	Object.defineProperty(target, key, {
		value,
		enumerable: true,
		writable: true,
		configurable: true,
	});
}

/** A Zod issue path as the operator writes it: its keys joined with dots. */
export function operatorPath(path: readonly PropertyKey[]): string {
	return path.map(String).join(".");
}

/**
 * What a composition root reads before it knows its modules (transitional):
 * the values at `reads` (the switches it chooses its modules by, its log
 * level), each parsed with the schema the transitional base declares at that
 * path (`pickConfigSchema`) and laid over `raw`, so every key it does not
 * read stays as written.
 *
 * Only `reads` is parsed. Before the modules are known, `raw` is resolved
 * over core's `reference.conf` alone, so a default only a package's
 * reference sets is missing, and a section it completes (an operator's
 * `rateLimit.limit` whose `windowSeconds` the package ships) would be refused
 * here though boot accepts it. Read no such section here. Use the answer to
 * choose the modules and for what the root needs before boot; hand
 * `createApp` the resolved configuration itself.
 *
 * An absent ancestor of a read path reads as the base's default, if any (no
 * `mfa` section: `mfa.mode` reads `"off"`, as boot does). A refused value is
 * a `RangeError` naming each operator path, with the Zod error as its
 * `cause`; so is a path the base does not declare as one schema, or one
 * beneath a value the base transforms whole (read the shorter path).
 *
 * Typed `AppConfig`, the type the module factories take, though only `reads`
 * is parsed: the base's own output type, every mirrored section optional, is
 * not one they accept.
 */
export function readTransitionalConfig(raw: unknown, reads: readonly string[]): AppConfig {
	const picked = pickConfigSchema(TransitionalConfigSchema, reads);
	let result: ReturnType<typeof picked.safeParse>;
	try {
		result = picked.safeParse(raw);
	} catch (thrown) {
		// A read that throws — a getter on a hand-built configuration — is a
		// refusal like any other, not an error escaping the reader.
		throw new RangeError(
			"Config validation failed — core's configuration schema threw instead of answering, so it could not be parsed synchronously; the error it threw is this error's cause",
			{ cause: thrown },
		);
	}
	if (!result.success) {
		const issues = result.error.issues as readonly z.core.$ZodIssue[];
		throw new RangeError(
			`Config validation failed — ${issues.length} issue(s) found: ${issues
				.map((issue) => `${operatorPath(issue.path) || "(the configuration)"}: ${issue.message}`)
				.join("; ")}`,
			{ cause: result.error },
		);
	}
	return overlayConfig(raw, result.data) as AppConfig;
}
