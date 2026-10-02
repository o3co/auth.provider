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
 * store generation, the conditional answers and their readers, at
 * `adapters/conditionalWrite.mts`) has not landed. This file holds only the
 * part of it the factor set's members are typed by, under the names the
 * convention plans, so `MfaFactorStore` can be built and proven against it
 * meanwhile. Nothing outside core's mfa module and its contract binding
 * imports it.
 *
 * When the convention lands, this file and its test are deleted, the
 * imports point at the convention, and core's root drops the stand-in block
 * that re-exports it. The convention decides every name and shape here;
 * `ConditionalSetRemoveAnswer` above all, whose name it has not given.
 */

/**
 * A store-owned generation: opaque, compared only with `===`. The store
 * issues a fresh one at every write of what it guards, and it never repeats
 * for one key: not after a delete and a re-create, and not when the new value
 * is byte-identical to an old one. So a per-key counter that restarts, a
 * digest of the value and a timestamp are none. The caller never computes or
 * orders one.
 */
export type StoreGeneration = string & { readonly __brand: "StoreGeneration" };

const GENERATION = /^[\x21-\x7e]{1,128}$/;

/** Whether `value` is a generation as a store may answer one: 1 to 128 visible ASCII characters. */
export const isStoreGeneration = (value: unknown): value is StoreGeneration =>
	typeof value === "string" && GENERATION.test(value);

/** A set's members and its generation, read as one snapshot. `generation` is `null` only for a set never written. */
export interface VersionedSet<T> {
	readonly generation: StoreGeneration | null;
	readonly items: readonly T[];
}

/**
 * What a conditional create answers: `created`, with the set's new
 * generation; or `conflict`, with nothing written.
 */
export type ConditionalCreateAnswer =
	| { readonly outcome: "created"; readonly generation: StoreGeneration }
	| { readonly outcome: "conflict" };

/**
 * What a conditional remove of a set's member answers: `removed`, with the
 * set's new generation, so a writer can chain its next write without a read;
 * `missing` or `conflict`, with nothing written.
 */
export type ConditionalSetRemoveAnswer =
	| { readonly outcome: "removed"; readonly generation: StoreGeneration }
	| { readonly outcome: "missing" }
	| { readonly outcome: "conflict" };

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * `read(answer)`, any throw of it a `RangeError` carrying the throw as its
 * cause: an answer that cannot be read is the store's outage.
 */
function readAnswer<T>(what: string, answer: unknown, read: (answer: unknown) => T): T {
	try {
		return read(answer);
	} catch (cause) {
		if (cause instanceof RangeError) throw cause;
		throw new RangeError(`${what}: the answer could not be read`, { cause });
	}
}

/**
 * A conditional create's answer as {@link ConditionalCreateAnswer} promises
 * it, as a fresh object. Throws a `RangeError` for anything else, which the
 * caller answers as the store's outage: never a write that happened, and
 * never one that did not.
 */
export function readConditionalCreateAnswer(answer: unknown): ConditionalCreateAnswer {
	return readAnswer("a conditional create", answer, (value) => {
		if (isRecord(value)) {
			const { outcome } = value;
			if (outcome === "conflict") return { outcome };
			if (outcome === "created") {
				const { generation } = value;
				if (isStoreGeneration(generation)) return { outcome, generation };
			}
		}
		throw new RangeError("a conditional create answered outside its promise");
	});
}

/**
 * A set's conditional remove's answer as {@link ConditionalSetRemoveAnswer}
 * promises it, as a fresh object. Throws a `RangeError` for anything else,
 * as {@link readConditionalCreateAnswer} does.
 */
export function readConditionalSetRemoveAnswer(answer: unknown): ConditionalSetRemoveAnswer {
	return readAnswer("a conditional remove", answer, (value) => {
		if (isRecord(value)) {
			const { outcome } = value;
			if (outcome === "missing" || outcome === "conflict") return { outcome };
			if (outcome === "removed") {
				const { generation } = value;
				if (isStoreGeneration(generation)) return { outcome, generation };
			}
		}
		throw new RangeError("a conditional remove answered outside its promise");
	});
}
