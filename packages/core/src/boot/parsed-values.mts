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
 * boot/parsed-values.mts: how stage 1 parses a piece of the configuration
 * with a schema a module declared — synchronously, a throw answered as an
 * issue — and the frozen copy of what the schema answered, which every
 * factory reading it receives. Shared by the modules' sections and the
 * `core.federations` entries dispatched to a type.
 */

import type { z } from "zod";
import { failureSummary } from "./failure-summary.mjs";

/**
 * A parsed section as every factory of its module receives it: plain data —
 * arrays, and objects whose prototype is `Object.prototype` or `null` —
 * copied and frozen all the way down, so no factory can change what another
 * reads, and a subtree the schema passed through (`z.unknown()`) is not the
 * `config` slot's own object. Anything else — a `URL`, a `Buffer`, a class
 * instance a transform built — is handed over as the schema made it: freezing
 * a typed array throws, and copying an instance would lose what it is.
 */
export function frozenSection(value: unknown, copies = new Map<object, unknown>()): unknown {
	if (value === null || typeof value !== "object") return value;
	const known = copies.get(value);
	if (known !== undefined) return known;
	if (Array.isArray(value)) {
		const copy: unknown[] = [];
		copies.set(value, copy);
		for (const item of value) copy.push(frozenSection(item, copies));
		return Object.freeze(copy);
	}
	const prototype: unknown = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) return value;
	// The same prototype as the original: `Object.prototype`, or none.
	const copy: object = prototype === null ? Object.setPrototypeOf({}, null) : {};
	copies.set(value, copy);
	for (const key of Reflect.ownKeys(value)) {
		if (!Object.prototype.propertyIsEnumerable.call(value, key)) continue;
		// Defined, not assigned: a key named `__proto__` stays a key.
		Object.defineProperty(copy, key, {
			value: frozenSection((value as Record<PropertyKey, unknown>)[key], copies),
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return Object.freeze(copy);
}

/**
 * Parse `value` with one schema of stage 1 — core's base or a module's
 * section — synchronously. A schema
 * that throws instead of answering — an async refinement (Zod cannot finish
 * it synchronously), or a transform or a getter that throws — is one more
 * issue at the root of what it parsed, naming `subject`, so it refuses boot
 * the way a refused value does rather than escaping stage 1 as a bare error.
 */
export function parseSection(
	schema: z.ZodType,
	value: unknown,
	subject = "the section's schema",
): { readonly data: unknown } | { readonly issues: readonly z.ZodIssue[] } {
	try {
		const result = schema.safeParse(value);
		return result.success ? { data: result.data } : { issues: result.error.issues };
	} catch (thrown) {
		return {
			issues: [
				{
					code: "custom",
					path: [],
					message: `${subject} threw instead of answering, so it could not be parsed synchronously: ${failureSummary(thrown)}`,
				} as z.ZodIssue,
			],
		};
	}
}
