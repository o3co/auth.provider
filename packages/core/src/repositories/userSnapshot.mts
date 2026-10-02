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
 * A login's one read of the `User` a repository answers: a plain snapshot of
 * the fields `User` declares, each read by name once, that everything the
 * login derives — and the session's `user` — is read from. It sits with
 * `User`, its owner, so a field added to `User` changes this file alone.
 *
 * Its copy (`readPlainFields`) is the by-name plain-data copy a login's
 * user and claims go through: session admission reads the claims envelope
 * a login records through it too, and core's client-record boundary
 * (`clientRepositoryBoundary.mts`) each client record. Core-internal: not
 * exported from the package.
 */

import type { User } from "./types.mjs";

/** The fields `User` declares; not its index signature. */
type DeclaredUserField = keyof {
	[K in keyof User as string extends K ? never : number extends K ? never : K]: unknown;
};

/**
 * The fields `User` declares, each read by name however the object holds
 * it. An entry `User` does not declare fails to compile here, and a field
 * `User` declares that this list misses fails to compile below.
 */
const USER_FIELDS = [
	"id",
	"username",
	"email",
	"emailVerified",
	"name",
	"picture",
	"groups",
	"mfaEnrolled",
] as const satisfies readonly DeclaredUserField[];

type UnreadUserField = Exclude<DeclaredUserField, (typeof USER_FIELDS)[number]>;
const everyDeclaredFieldRead: [UnreadUserField] extends [never] ? true : UnreadUserField = true;
void everyDeclaredFieldRead;

/** What `readUserSnapshot` answers: the snapshot, or why the `User` is refused. */
export type UserSnapshotReading =
	| { readonly ok: true; readonly snapshot: Readonly<Record<string, unknown>> }
	| { readonly ok: false; readonly refused: "not_an_object" | "id" }
	| {
			readonly ok: false;
			readonly refused: "not_plain_data";
			readonly field: (typeof USER_FIELDS)[number];
	  };

/** What `copyByName` throws for a value that is not plain data. */
class NotPlainData extends Error {}

/** What `copies` holds for an object found not plain data, or being copied. */
const NOT_PLAIN: unique symbol = Symbol("not plain data");
const COPYING: unique symbol = Symbol("being copied");

/** Whether `key` is an array index as an array's own property names spell one. */
const isArrayIndex = (key: string): boolean =>
	/^(0|[1-9][0-9]*)$/.test(key) && Number(key) < 2 ** 32 - 1;

/** Whether `value`'s prototype is `Object.prototype` or `null`: a plain object, not an instance. */
const hasPlainPrototype = (value: object): boolean => {
	const prototype = Reflect.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
};

/**
 * `value` copied by name as plain data — what JSON holds as it is — frozen
 * at every depth and sharing nothing with it. A declared field from an
 * untyped Store may hold any JSON value, which the login reads as its own
 * verdict (an `email` that is a list is `unreadable`), so arrays and plain
 * objects are copied, not only `groups`' strings:
 *
 * - a string, a boolean, `null`, or a finite number, as it is;
 * - an array (`Array.isArray`, whatever its prototype — an ORM's list type
 *   included), its `length` and each of its own indices read once, in
 *   index order, copied as a plain array; one with a hole or an `undefined`
 *   is not plain data;
 * - an object whose prototype is `Object.prototype` or `null`, each own
 *   enumerable string key read once, one read as `undefined` left out.
 *
 * Anything else is not plain data and throws `NotPlainData`: a bigint, a
 * non-finite number, a symbol, a function, `undefined`, an instance (a
 * `Date`, a `Map`, a class's), and a cycle. Every read is an ordinary one,
 * so an accessor runs, and a throw is let through as it was thrown.
 * `copies` keeps an object two fields share one copy, read once, and
 * remembers an object found not plain data, so it is not read again.
 */
function copyByName(value: unknown, copies: Map<object, unknown>): unknown {
	if (value === null) return null;
	switch (typeof value) {
		case "string":
		case "boolean":
			return value;
		case "number":
			if (Number.isFinite(value)) return value;
			throw new NotPlainData();
		case "object":
			break;
		default:
			throw new NotPlainData();
	}
	const source = value as Record<string, unknown>;
	const known = copies.get(source);
	if (known === NOT_PLAIN || known === COPYING) throw new NotPlainData();
	if (known !== undefined) return known;
	copies.set(source, COPYING);
	try {
		const copy = Array.isArray(source) ? copyArray(source, copies) : copyObject(source, copies);
		copies.set(source, copy);
		return copy;
	} catch (err) {
		if (err instanceof NotPlainData) copies.set(source, NOT_PLAIN);
		throw err;
	}
}

function copyArray(source: readonly unknown[], copies: Map<object, unknown>): readonly unknown[] {
	const length = source.length;
	// In index order, whatever order the keys are listed in (a Proxy chooses
	// its own): exactly 0 to length - 1, or the list has a hole.
	const indices = Object.getOwnPropertyNames(source)
		.filter(isArrayIndex)
		.map(Number)
		.sort((a, b) => a - b);
	if (indices.length !== length || indices.some((index, at) => index !== at)) {
		throw new NotPlainData();
	}
	const copy: unknown[] = [];
	for (const index of indices) {
		const element = source[index];
		if (element === undefined) throw new NotPlainData();
		copy.push(copyByName(element, copies));
	}
	return Object.freeze(copy);
}

function copyObject(
	source: Record<string, unknown>,
	copies: Map<object, unknown>,
): Readonly<Record<string, unknown>> {
	if (!hasPlainPrototype(source)) throw new NotPlainData();
	const copy: Record<string, unknown> = {};
	for (const key of Object.keys(source)) {
		const field = source[key];
		if (field !== undefined) define(copy, key, copyByName(field, copies));
	}
	return Object.freeze(copy);
}

/** `copy[key] = value`, as an own data property even for `__proto__`. */
function define(copy: Record<string, unknown>, key: string, value: unknown): void {
	Object.defineProperty(copy, key, { value, enumerable: true, writable: true, configurable: true });
}

/** What `readPlainFields` answers: the fields copied, or the first that is not plain data. */
export type PlainFieldsReading<F extends string> =
	| { readonly ok: true; readonly copy: Readonly<Record<string, unknown>> }
	| { readonly ok: false; readonly field: F };

/**
 * `fields` of `record`, each read by name once — however the object holds
 * it: own data, an accessor, inherited, behind a Proxy — and copied as
 * plain data (`copyByName`), into one object frozen at every depth that
 * shares nothing with `record`. A field named twice is read once; one read
 * as `undefined` is left out; nothing else of `record` is read.
 *
 * Answers the first field holding what is not plain data. `record` is a
 * record, not a value: a field that refers back to it is not plain data,
 * and it is not read again. A read that throws is let through as it was
 * thrown.
 */
export function readPlainFields<F extends string>(
	record: object,
	fields: Iterable<F>,
): PlainFieldsReading<F> {
	const source = record as Record<string, unknown>;
	const copy: Record<string, unknown> = {};
	// One map for every field: an object two fields share is read once.
	const copies = new Map<object, unknown>([[source, NOT_PLAIN]]);
	for (const field of new Set(fields)) {
		const value = source[field];
		if (value === undefined) continue;
		try {
			define(copy, field, copyByName(value, copies));
		} catch (err) {
			if (!(err instanceof NotPlainData)) throw err;
			return { ok: false, field };
		}
	}
	return { ok: true, copy: Object.freeze(copy) };
}

/**
 * The plain snapshot a login takes of `user`, its one read of it: each field
 * `User` declares, read by name, once, however the object holds it — own
 * data, an accessor, inherited, as a class instance or an ORM entity holds
 * it — and nothing else of it (`readPlainFields`). A field read as
 * `undefined` is left out. Frozen at every depth, sharing nothing with
 * `user`.
 *
 * Refused: a `user` that is not an object (`not_an_object`); a declared
 * field holding what is not plain data (`not_plain_data`, naming it), which
 * left out would read the witness as not enrolled; an `id` that is not a
 * non-empty string (`id`). The user is a record, not a value: a field that
 * refers back to it is not plain data, and it is not read again. A read
 * that throws is let through as it was thrown: never read as a witness or
 * an address.
 */
export function readUserSnapshot(user: unknown): UserSnapshotReading {
	if (typeof user !== "object" || user === null || Array.isArray(user)) {
		return { ok: false, refused: "not_an_object" };
	}
	const reading = readPlainFields(user, USER_FIELDS);
	if (!reading.ok) return { ok: false, refused: "not_plain_data", field: reading.field };
	const snapshot = reading.copy;
	if (typeof snapshot.id !== "string" || snapshot.id.length === 0) {
		return { ok: false, refused: "id" };
	}
	return { ok: true, snapshot };
}
