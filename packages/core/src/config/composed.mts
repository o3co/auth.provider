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
 * {@link readTransitionalConfig} is step 1 and 2 alone, for the one read a
 * composition root still makes before it knows its modules. Both go when the
 * move pull requests have taken each mirrored section out of core's schema
 * and the composition root reads only its own section first (#728).
 */

import type { z } from "zod";
import { type AppConfig, CoreConfigSchema, fullSectionsSchema } from "./application.schema.mjs";

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
 * `over` laid on `under`, key by key through plain objects: where both hold
 * an object, their keys are merged the same way; anywhere else `over`'s value
 * wins, unless it is `undefined`, which leaves `under`'s. A key only `under`
 * has is kept — which is how a key a schema does not declare survives the
 * schema's parse. Neither input is changed: every object on a merged path is
 * a new one, and a value only one side holds is that side's own.
 */
export function overlayConfig(under: unknown, over: unknown): unknown {
	if (over === undefined) return under;
	if (!isPlainConfigObject(under) || !isPlainConfigObject(over)) return over;
	const merged: Record<string, unknown> = {};
	for (const key of Object.keys(under)) defineConfigKey(merged, key, under[key]);
	for (const key of Object.keys(over)) {
		defineConfigKey(
			merged,
			key,
			Object.hasOwn(under, key) ? overlayConfig(under[key], over[key]) : over[key],
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
 * transitional): `raw` — the configuration it resolved — parsed with the
 * transitional base and laid over what was written, so it reads every switch
 * with the coercions it always got and a key no schema declares is kept.
 *
 * Use its answer to choose the modules, and for what the root needs before
 * boot (the log level); hand `createApp` the resolved configuration itself,
 * which boot parses once with the modules' schemas too. It goes when the
 * composition root's switches move into its own section, the only one read
 * before the modules are chosen.
 *
 * A value the base refuses is a `RangeError` naming each operator path, with
 * the Zod error as its `cause`.
 */
export function readTransitionalConfig(raw: unknown): AppConfig {
	const result = TransitionalConfigSchema.safeParse(raw);
	if (!result.success) {
		const issues = result.error.issues as readonly z.core.$ZodIssue[];
		throw new RangeError(
			`Config validation failed — ${issues.length} issue(s) found: ${issues
				.map((issue) => `${operatorPath(issue.path)}: ${issue.message}`)
				.join("; ")}`,
			{ cause: result.error },
		);
	}
	return overlayConfig(raw, result.data) as AppConfig;
}
