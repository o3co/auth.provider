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
 * STAND-IN, NOT A CONVENTION. Core's conditional-write convention (the
 * store generation, versioned reads, the conditional answers and their
 * readers, at `adapters/conditionalWrite.mts`) has not landed. This file
 * holds only the set-scoped part of it the factor set's members are typed
 * by, under the convention's names and shapes, so `MfaFactorStore` can be
 * built and proven against it meanwhile. Nothing outside core's mfa module
 * and its contract binding uses it.
 *
 * When the convention lands, this file and its test are deleted, the
 * imports point at the convention, and core's root drops the stand-in block
 * that re-exports it. The convention decides every name and shape here.
 */

import { randomUUID } from "node:crypto";

declare const storeGenerationBrand: unique symbol;

/**
 * The generation a store issued for one set's membership: opaque, compared
 * only with `===`. Fresh on every write of what it guards. Never issued
 * twice for one key: not after a delete and a re-create, and not for a
 * byte-identical value. So it is never a counter, a digest or a timestamp.
 * Only the store makes one; a caller only hands back one it was given.
 */
export type StoreGeneration = string & { readonly [storeGenerationBrand]: true };

/** Whether `value` is a generation a store may answer: 1 to 128 visible ASCII characters (0x21–0x7e). Never throws. */
export function isStoreGeneration(value: unknown): value is StoreGeneration {
	return typeof value === "string" && /^[\x21-\x7e]{1,128}$/.test(value);
}

/** A fresh generation: a random UUID. One way for a store that makes its own. */
export function newStoreGeneration(): StoreGeneration {
	return randomUUID() as StoreGeneration;
}

/**
 * The write-lifetime bound of the bundled stores: every write they take
 * commits or fails within it, and an emptied set's tombstone is kept for at
 * least this long. 24 hours. STAND-IN: the convention owns this constant and
 * its name; this one is dropped when it lands.
 */
export const BUNDLED_STORE_WRITE_LIFETIME_MS = 24 * 60 * 60 * 1000;

/**
 * A set's members and the set's generation, from one snapshot. `generation`
 * is `null` only for a set never written, or whose tombstone has passed.
 * A set's generation outlives its members, and an emptied set's tombstone
 * is kept for at least the store's write-lifetime bound (24 h for the
 * bundled stores).
 */
export interface VersionedSet<T> {
	readonly items: readonly T[];
	readonly generation: StoreGeneration | null;
}

/**
 * Adding one member to a set, only while the set is at the expected
 * generation (`null`: only while it was never written). Never `missing`.
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

/** `answer[key]`, read once; a `TypeError` naming `what` for a non-object or a read that throws. */
const field = (answer: unknown, key: string, what: string): unknown => {
	if (typeof answer !== "object" || answer === null) throw new TypeError(`${what}: not an object`);
	try {
		return (answer as Record<string, unknown>)[key];
	} catch {
		throw new TypeError(`${what}: ${key} could not be read`);
	}
};

/**
 * Core's readers of what a store answered. Each property is read once, and
 * a fresh frozen object is returned. Anything outside the type (another
 * outcome, a malformed generation, a property read that throws, `undefined`
 * where `null` is meant) is a `TypeError` naming the field, never a value.
 * The caller treats that as the store's outage: never as a write that
 * happened, and never as one that did not. A `RangeError` stays reserved for
 * a caller's own input.
 */
export function readVersionedSet<T>(answer: VersionedSet<T>): VersionedSet<T> {
	const what = "versioned set";
	if (Array.isArray(answer)) throw new TypeError(`${what}: not an object`);
	const generation = field(answer, "generation", what);
	if (generation !== null && !isStoreGeneration(generation)) {
		throw new TypeError(`${what}: malformed generation`);
	}
	const items = field(answer, "items", what);
	if (!Array.isArray(items)) throw new TypeError(`${what}: items is not a list`);
	return Object.freeze({ items: Object.freeze([...(items as T[])]), generation });
}

/** A conditional create's answer as {@link ConditionalCreateAnswer} promises it; a `TypeError` for anything else. */
export function readConditionalCreateAnswer(answer: unknown): ConditionalCreateAnswer {
	const what = "conditional create answer";
	const outcome = field(answer, "outcome", what);
	if (outcome === "conflict") return Object.freeze({ outcome });
	if (outcome !== "created") throw new TypeError(`${what}: unknown outcome`);
	const generation = field(answer, "generation", what);
	if (!isStoreGeneration(generation)) throw new TypeError(`${what}: malformed generation`);
	return Object.freeze({ outcome, generation });
}

/**
 * A set's conditional remove's answer as {@link ConditionalSetRemoveAnswer}
 * promises it; a `TypeError` for anything else, a `removed` without the
 * set's new generation among it.
 */
export function readConditionalSetRemoveAnswer(answer: unknown): ConditionalSetRemoveAnswer {
	const what = "conditional set remove answer";
	const outcome = field(answer, "outcome", what);
	if (outcome === "missing" || outcome === "conflict") return Object.freeze({ outcome });
	if (outcome !== "removed") throw new TypeError(`${what}: unknown outcome`);
	const generation = field(answer, "generation", what);
	if (!isStoreGeneration(generation)) throw new TypeError(`${what}: malformed generation`);
	return Object.freeze({ outcome, generation });
}
