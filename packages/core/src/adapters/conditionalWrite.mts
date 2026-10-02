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
 * The conditional-write convention: a generation a store issues for what it
 * guards, a value read with its generation, and the answers of a write applied
 * only at the generation the caller read. The rules every store keeps are
 * stated once, in docs/adapter-surface.md, "Conditional writes".
 */

import { randomUUID } from "node:crypto";

declare const storeGenerationBrand: unique symbol;

/**
 * The generation a store issued for one record, or for one set's membership:
 * opaque, compared only with `===`. Fresh on every write of what it guards,
 * the create included. Never issued twice for one key: not after a delete and
 * a re-create, and not for a byte-identical value. So it is never a counter,
 * a digest or a timestamp. Only the store makes one; a caller only hands
 * back one it was given.
 */
export type StoreGeneration = string & { readonly [storeGenerationBrand]: true };

const GENERATION_SHAPE = /^[\x21-\x7e]{1,128}$/;

/** Whether `value` is a generation a store may answer: 1 to 128 visible ASCII characters (0x21–0x7e). Never throws. */
export function isStoreGeneration(value: unknown): value is StoreGeneration {
	return typeof value === "string" && GENERATION_SHAPE.test(value);
}

/** A fresh generation: a random UUID. One way for a store that makes its own. */
export function newStoreGeneration(): StoreGeneration {
	return randomUUID() as StoreGeneration;
}

/**
 * The bundled stores' write-lifetime bound: a membership write commits or
 * fails, server-side, well within it, and an emptied set's tombstone is kept
 * for at least this long. 24 hours.
 */
export const BUNDLED_STORE_WRITE_LIFETIME_MS = 24 * 60 * 60 * 1000;

/** A stored record and the generation it was read at, from one snapshot. */
export interface Versioned<T> {
	readonly value: T;
	readonly generation: StoreGeneration;
}

/**
 * A set's members and the set's generation, from one snapshot. `generation`
 * is `null` only for an absent set: never written, or its tombstone expired.
 * A set's generation outlives its members, and an emptied set's tombstone is
 * kept for at least the store's write-lifetime bound
 * ({@link BUNDLED_STORE_WRITE_LIFETIME_MS} for the bundled stores).
 */
export interface VersionedSet<T> {
	readonly items: readonly T[];
	readonly generation: StoreGeneration | null;
}

/**
 * A record-scoped replace, applied only while the record is at the expected
 * generation, as one atomic step in the store. It never creates a record.
 * - `updated`: written; `generation` is the record's new one.
 * - `missing`: no live record (absent, removed or past the store's retention).
 *   Nothing was written, and nothing was added to any listing.
 * - `conflict`: the record is live at another generation. Nothing was written.
 * A store that cannot tell rejects; it never answers `missing` for an outage.
 * A rejection after the request was sent means "unknown", never "not written".
 */
export type ConditionalReplaceAnswer =
	| { readonly outcome: "updated"; readonly generation: StoreGeneration }
	| { readonly outcome: "missing" }
	| { readonly outcome: "conflict" };

/** A record-scoped delete, applied only while the record is at the expected generation. The outcomes as for a replace. */
export type ConditionalRemoveAnswer =
	| { readonly outcome: "removed" }
	| { readonly outcome: "missing" }
	| { readonly outcome: "conflict" };

/**
 * Adding one member to a set, only while the set is at the expected
 * generation (`null`: only while the set is absent). Never `missing`.
 * `conflict` covers a set at another generation, a set absent where
 * `expected` names one, a set present where `expected` is `null`, and a
 * member id already held. Nothing is written on `conflict`.
 */
export type ConditionalCreateAnswer =
	| { readonly outcome: "created"; readonly generation: StoreGeneration }
	| { readonly outcome: "conflict" };

/**
 * Removing one member of a set, only while the set is at the expected
 * generation. `removed` carries the set's new generation: the set stays,
 * even when it is now empty. `missing`: no set, or no such member at
 * `expected`, with nothing written and the generation unchanged.
 * `conflict`: the set is at another generation. The generation is checked
 * before the member.
 */
export type ConditionalSetRemoveAnswer =
	| { readonly outcome: "removed"; readonly generation: StoreGeneration }
	| { readonly outcome: "missing" }
	| { readonly outcome: "conflict" };

/*
 * Core's readers of what a store answered. Each property is read once, and a
 * fresh frozen object is returned. Anything outside the type (another outcome,
 * a malformed generation, a property read that throws, `undefined` where
 * `null` is meant) is a TypeError naming the field, never a value. The caller
 * treats that as the store's outage: never as a write that happened, and
 * never as one that did not. A RangeError stays reserved for a caller's own
 * input.
 */

/** `answer[key]`, read once; a TypeError when `answer` is no object or the read throws. */
const field = (answer: unknown, key: string, what: string): unknown => {
	if (typeof answer !== "object" || answer === null) throw new TypeError(`${what}: not an object`);
	try {
		return (answer as Record<string, unknown>)[key];
	} catch {
		throw new TypeError(`${what}: ${key} could not be read`);
	}
};

/** `answer.generation`, read once and required to be a well-formed generation. */
const generationOf = (answer: unknown, what: string): StoreGeneration => {
	const generation = field(answer, "generation", what);
	if (!isStoreGeneration(generation)) throw new TypeError(`${what}: generation is malformed`);
	return generation;
};

/** `answer.outcome`, read once and required to be one of `outcomes`. */
const outcomeOf = <O extends string>(answer: unknown, outcomes: readonly O[], what: string): O => {
	const outcome = field(answer, "outcome", what);
	if (!(outcomes as readonly unknown[]).includes(outcome)) {
		throw new TypeError(`${what}: outcome is not one of ${outcomes.join(", ")}`);
	}
	return outcome as O;
};

/** A versioned read: `null` when the store holds no live record, else the value and its generation. */
export function readVersioned<T>(answer: Versioned<T> | null): Versioned<T> | null {
	if (answer === null) return null;
	const what = "versioned read";
	const value = field(answer, "value", what) as T;
	const generation = generationOf(answer, what);
	return Object.freeze({ value, generation });
}

/** A versioned set read: the items copied into a new frozen array, each item the port's to judge. */
export function readVersionedSet<T>(answer: VersionedSet<T>): VersionedSet<T> {
	const what = "versioned set read";
	const items = field(answer, "items", what);
	if (!Array.isArray(items)) throw new TypeError(`${what}: items is not an array`);
	let copy: T[];
	try {
		copy = Array.from(items as readonly T[]);
	} catch {
		throw new TypeError(`${what}: items could not be read`);
	}
	const generation = field(answer, "generation", what);
	if (generation !== null && !isStoreGeneration(generation)) {
		throw new TypeError(`${what}: generation is malformed`);
	}
	return Object.freeze({ items: Object.freeze(copy), generation });
}

/** A conditional replace's answer. */
export function readConditionalReplaceAnswer(answer: unknown): ConditionalReplaceAnswer {
	const what = "conditional replace answer";
	const outcome = outcomeOf(answer, ["updated", "missing", "conflict"], what);
	if (outcome !== "updated") return Object.freeze({ outcome });
	return Object.freeze({ outcome, generation: generationOf(answer, what) });
}

/** A record-scoped conditional remove's answer: the outcome alone. */
export function readConditionalRemoveAnswer(answer: unknown): ConditionalRemoveAnswer {
	const outcome = outcomeOf(
		answer,
		["removed", "missing", "conflict"],
		"conditional remove answer",
	);
	return Object.freeze({ outcome });
}

/** A conditional create's answer. */
export function readConditionalCreateAnswer(answer: unknown): ConditionalCreateAnswer {
	const what = "conditional create answer";
	const outcome = outcomeOf(answer, ["created", "conflict"], what);
	if (outcome !== "created") return Object.freeze({ outcome });
	return Object.freeze({ outcome, generation: generationOf(answer, what) });
}

/** A set-scoped conditional remove's answer: `removed` always with the set's new generation. */
export function readConditionalSetRemoveAnswer(answer: unknown): ConditionalSetRemoveAnswer {
	const what = "conditional set remove answer";
	const outcome = outcomeOf(answer, ["removed", "missing", "conflict"], what);
	if (outcome !== "removed") return Object.freeze({ outcome });
	return Object.freeze({ outcome, generation: generationOf(answer, what) });
}
