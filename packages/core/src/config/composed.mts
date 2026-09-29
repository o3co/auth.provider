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
 * The configuration as boot's one composed parse reads it (#728), while core's
 * schema still mirrors sections other packages own.
 *
 * A composition root hands `createApp` the configuration it resolved — the
 * HOCON it layered, never parsed first — and boot parses it once:
 *
 * 1. with the transitional base, {@link TransitionalConfigSchema}: core's own
 *    sections, and every section core's schema still mirrors for a package,
 *    each optional — the coercions and checks an operator's value always got,
 *    none of the mirrored sections required;
 * 2. laid over what was written ({@link overlayConfig}), so a key no schema
 *    declares is kept, not stripped;
 * 3. then by the modules' own `configSchema`s, and by each module's section
 *    schema at its path, which boot writes back there.
 *
 * {@link readTransitionalConfig} is step 1 and 2 over the paths a composition
 * root reads before it knows its modules, alone. Both go when the
 * move pull requests have taken each mirrored section out of core's schema
 * and the composition root reads only its own section first (#728).
 */

import type { z } from "zod";
import { type AppConfig, CoreConfigSchema, fullSectionsSchema } from "./application.schema.mjs";
import { pickConfigSchema } from "./schema-path.mjs";

/**
 * The transitional base of boot's one composed parse (#728): core's own
 * sections, required as before, and every section `fullSectionsSchema`
 * mirrors for another package's module, made optional — each keeps the
 * coercions and checks it applied (a `${?VAR}` string read as a number or a
 * boolean, a value outside its vocabulary refused), and none has to be
 * present. A mirrored section is therefore still validated when a
 * configuration carries it, loaded module or not, until the move pull
 * request for its package takes the mirror out of core's schema.
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
 * `over` — a schema's parse — laid on `under` — what was written — key by
 * key through plain objects (`isPlainConfigObject`):
 *
 * - where both hold a plain object, their keys are merged the same way;
 * - anywhere else the parsed value wins, whole: a list, a `URL`, a value
 *   whose type the schema changed;
 * - a key the parse holds as `undefined` is removed — the schema made
 *   nothing of the value written there (an empty environment variable read
 *   as unset), and the value it did not accept is not kept;
 * - a key the parse does not hold is kept as written — the schema did not
 *   declare it, and stripped it — which is how a key no schema declares
 *   survives the parse.
 *
 * No `over` at all (`undefined`) answers `under`. Neither input is changed:
 * every object on a merged path is a new one, and a value only one side
 * holds is that side's own.
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
 * What a composition root reads before it knows its modules (#728,
 * transitional): the values at `reads` — the switches it chooses its modules
 * by, its log level — each parsed with the schema core's transitional base
 * declares at that path (`pickConfigSchema`), with the coercions it always
 * got, and laid over `raw`, the configuration it resolved, so every key it
 * does not read stays as written.
 *
 * Only `reads` is parsed. Boot parses the whole configuration once, over
 * every loaded package's `reference.conf`, and refuses what is wrong there;
 * before the modules are known, a composition root resolves its own files
 * over core's `reference.conf` alone, so a default only a package's reference
 * sets is not in `raw` yet — and a section it completes (an operator's
 * `rateLimit.limit` whose `windowSeconds` the package ships) would be refused
 * here, though boot accepts it. Read no such section here.
 *
 * Use its answer to choose the modules, and for what the root needs before
 * boot; hand `createApp` the resolved configuration itself. It goes when the
 * composition root's switches move into its own section, the only one read
 * before the modules are chosen.
 *
 * An absent ancestor of a read path reads as the default the base declares
 * for it, if any (with no `mfa` section, `mfa.mode` reads `"off"`, as boot
 * does). A read value the schema refuses is a `RangeError` naming each
 * operator path, with the Zod error as its `cause`; so is a path the base does
 * not declare as one schema, and one beneath a value the base transforms as a
 * whole (read the shorter path).
 *
 * Typed `AppConfig`, the type the module factories a composition root builds
 * from it take, though only `reads` is parsed: the transitional base's own
 * output type, every mirrored section optional, is not one they accept.
 */
export function readTransitionalConfig(raw: unknown, reads: readonly string[]): AppConfig {
	const result = pickConfigSchema(TransitionalConfigSchema, reads).safeParse(raw);
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
