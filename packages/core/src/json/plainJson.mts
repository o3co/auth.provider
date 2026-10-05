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
 * The one rule for a value JSON gives back as it is, and the copy taken by
 * it: each field read once, frozen at every depth, so whatever acts on the
 * copy acts on what was checked, and nothing a reader runs (a getter, a
 * Proxy trap) can answer one thing to the check and another to the writer.
 *
 * Taken as it is:
 * - `null`, a boolean, a string, a finite number other than `-0` (JSON writes
 *   it as `0`);
 * - a plain array (prototype `Array.prototype`): its `length` read once, its
 *   own keys exactly its indices — a hole, or a field of its own JSON would
 *   drop, is refused — each index read once; `undefined` in it is refused,
 *   since JSON would write `null`;
 * - a plain object (prototype `Object.prototype` or none, read once): each
 *   own key read once — an own getter runs once — one read as `undefined`
 *   left out as JSON leaves it out, an own `__proto__` kept as the field it is.
 *
 * Every own key of either must be one JSON writes — a string, enumerable — so
 * a symbol's field or a hidden one, a hidden `toJSON` among them, is refused
 * rather than lost. An object two fields share is copied once.
 *
 * Anything else is refused, naming where: a class's instance, an Array
 * subclass, a built-in (a Date, a Map, a RegExp, a boxed number, a Proxy over
 * any of them), a function, a symbol, a bigint, `undefined`, NaN, an
 * infinity, `-0`, a cycle, a read that throws, and nesting past the stack, the
 * copy's or JSON's. So a value is taken whole or not at all, never in part.
 */

/**
 * What {@link copyPlainJson} answers: the frozen copy, or where the value is
 * not one JSON gives back as it is — a path from the value itself, `""` for
 * the value, `.name` for an object's field and `[index]` for a list's entry
 * (`.a[0].b`). The keys are written as they are, not escaped, so a key
 * holding `.` or `[` reads as more than one step; the path is for a reader,
 * never parsed. It is as long as the nesting it names: a value nested
 * thousands deep is refused at a path thousands of steps long.
 */
export type PlainJsonCopy =
	| { readonly ok: true; readonly copy: unknown }
	| { readonly ok: false; readonly at: string };

/** Where a refusal was met: thrown from inside the copy, caught once at its top. */
interface Refusal {
	readonly at: string;
}

/**
 * The refusals the copy threw. A thrown value is told apart by membership
 * alone, so nothing of it runs — a Proxy's traps included — while it is.
 */
const refusals = new WeakSet<object>();

/** A refusal at `at`, to be thrown. */
const refused = (at: string): Refusal => {
	const refusal = Object.freeze({ at });
	refusals.add(refusal);
	return refusal;
};

/** Whether `thrown` is one of the copy's refusals, asked without running any of its code. */
const isRefusal = (thrown: unknown): thrown is Refusal =>
	typeof thrown === "object" && thrown !== null && refusals.has(thrown);

/** What `copies` holds for an object while it is copied: met again inside itself, it is a cycle. */
const COPYING: unique symbol = Symbol("being copied");

/**
 * `value` as its plain JSON copy (see this file's header), or where it is not
 * one. Never throws: whatever a read throws, a Proxy's trap included, is a
 * refusal there, and nothing of the thrown value is run to tell.
 */
export function copyPlainJson(value: unknown): PlainJsonCopy {
	try {
		const copy = copyAt(value, "", new Map());
		// Written once here, so a copy JSON cannot write — nesting a shared object
		// keeps shallow for the copy, deep for JSON — is refused where it is taken.
		JSON.stringify(copy);
		return { ok: true, copy };
	} catch (thrown) {
		return { ok: false, at: isRefusal(thrown) ? thrown.at : "" };
	}
}

/** `value`'s copy at `at`; a read that throws there is a refusal there. */
function copyAt(value: unknown, at: string, copies: Map<object, unknown>): unknown {
	try {
		return copyPlain(value, at, copies);
	} catch (thrown) {
		throw isRefusal(thrown) ? thrown : refused(at);
	}
}

function copyPlain(value: unknown, at: string, copies: Map<object, unknown>): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") {
		if (Number.isFinite(value) && !Object.is(value, -0)) return value;
		throw refused(at);
	}
	if (typeof value !== "object") throw refused(at);
	const known = copies.get(value);
	if (known === COPYING) throw refused(at);
	if (known !== undefined) return known;
	copies.set(value, COPYING);
	const prototype = Object.getPrototypeOf(value);
	const list = Array.isArray(value);
	if (list ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
		throw refused(at);
	}
	const copy = list
		? copyList(value as readonly unknown[], at, copies)
		: copyFields(value, at, copies);
	copies.set(value, copy);
	return copy;
}

/**
 * `value`'s own keys, listed once, when each is a field JSON writes: a string
 * key, enumerable — else refused, since a field JSON would skip (a symbol's,
 * a hidden one) or call (a hidden `toJSON`) is content the copy would lose.
 * A list's `length` is not a field.
 */
function fieldsOf(value: object, list: boolean, at: string): string[] {
	const fields: string[] = [];
	for (const key of Reflect.ownKeys(value)) {
		if (list && key === "length") continue;
		if (typeof key !== "string" || !Object.prototype.propertyIsEnumerable.call(value, key)) {
			throw refused(at);
		}
		fields.push(key);
	}
	return fields;
}

function copyList(
	list: readonly unknown[],
	at: string,
	copies: Map<object, unknown>,
): readonly unknown[] {
	const length = list.length;
	const keys = fieldsOf(list, true, at);
	if (keys.length !== length || keys.some((key, index) => key !== String(index))) {
		throw refused(at);
	}
	const copy: unknown[] = [];
	for (let index = 0; index < length; index++) {
		const entryAt = `${at}[${index}]`;
		let entry: unknown;
		try {
			entry = list[index];
		} catch {
			throw refused(entryAt);
		}
		if (entry === undefined) throw refused(entryAt);
		copy.push(copyAt(entry, entryAt, copies));
	}
	return Object.freeze(copy);
}

function copyFields(
	value: object,
	at: string,
	copies: Map<object, unknown>,
): Readonly<Record<string, unknown>> {
	const source = value as Readonly<Record<string, unknown>>;
	const copy: Record<string, unknown> = {};
	for (const key of fieldsOf(source, false, at)) {
		const fieldAt = `${at}.${key}`;
		let field: unknown;
		try {
			field = source[key];
		} catch {
			throw refused(fieldAt);
		}
		if (field === undefined) continue;
		// Defined, not assigned: an own `__proto__` stays the field it is.
		Object.defineProperty(copy, key, {
			value: copyAt(field, fieldAt, copies),
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return Object.freeze(copy);
}
