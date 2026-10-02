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
 * The convention's types: a generation is only ever one a store made, so a
 * plain string is not one; each answer is a closed union over its outcomes,
 * and only the outcomes that carry a generation name one. Asserted with
 * conditional types, which hold only under the TypeScript checker.
 */

import { describe, expectTypeOf, it } from "vitest";
import type {
	ConditionalCreateAnswer,
	ConditionalRemoveAnswer,
	ConditionalReplaceAnswer,
	ConditionalSetRemoveAnswer,
	StoreGeneration,
	Versioned,
	VersionedSet,
} from "#/index.mjs";

/** The `generation` an answer of outcome `O` carries, or `never` when it carries none. */
type GenerationOf<A, O> = A extends { readonly outcome: O; readonly generation: infer G }
	? G
	: never;

describe("StoreGeneration", () => {
	it("is not assignable from a plain string, and is assignable to one", () => {
		expectTypeOf<string>().not.toExtend<StoreGeneration>();
		expectTypeOf<StoreGeneration>().toExtend<string>();
	});
});

describe("Versioned and VersionedSet", () => {
	it("carry the value or items and the generation, the set's null only when never written", () => {
		expectTypeOf<Versioned<number>>().toEqualTypeOf<{
			readonly value: number;
			readonly generation: StoreGeneration;
		}>();
		expectTypeOf<VersionedSet<number>>().toEqualTypeOf<{
			readonly items: readonly number[];
			readonly generation: StoreGeneration | null;
		}>();
	});
});

describe("the answers are closed unions", () => {
	it("a replace answers updated with a generation, missing or conflict", () => {
		expectTypeOf<ConditionalReplaceAnswer["outcome"]>().toEqualTypeOf<
			"updated" | "missing" | "conflict"
		>();
		expectTypeOf<
			GenerationOf<ConditionalReplaceAnswer, "updated">
		>().toEqualTypeOf<StoreGeneration>();
		expectTypeOf<GenerationOf<ConditionalReplaceAnswer, "missing" | "conflict">>().toBeNever();
	});

	it("a record remove answers removed, missing or conflict, none with a generation", () => {
		expectTypeOf<ConditionalRemoveAnswer["outcome"]>().toEqualTypeOf<
			"removed" | "missing" | "conflict"
		>();
		expectTypeOf<GenerationOf<ConditionalRemoveAnswer, string>>().toBeNever();
	});

	it("a create answers created with a generation, or conflict, never missing", () => {
		expectTypeOf<ConditionalCreateAnswer["outcome"]>().toEqualTypeOf<"created" | "conflict">();
		expectTypeOf<
			GenerationOf<ConditionalCreateAnswer, "created">
		>().toEqualTypeOf<StoreGeneration>();
		expectTypeOf<GenerationOf<ConditionalCreateAnswer, "conflict">>().toBeNever();
	});

	it("a set remove answers removed with the set's generation, missing or conflict", () => {
		expectTypeOf<ConditionalSetRemoveAnswer["outcome"]>().toEqualTypeOf<
			"removed" | "missing" | "conflict"
		>();
		expectTypeOf<
			GenerationOf<ConditionalSetRemoveAnswer, "removed">
		>().toEqualTypeOf<StoreGeneration>();
		expectTypeOf<GenerationOf<ConditionalSetRemoveAnswer, "missing" | "conflict">>().toBeNever();
	});

	it("a switch over each outcome is exhaustive", () => {
		const replace = (a: ConditionalReplaceAnswer): string => {
			switch (a.outcome) {
				case "updated":
					return a.generation;
				case "missing":
				case "conflict":
					return a.outcome;
				default:
					return a satisfies never;
			}
		};
		const setRemove = (a: ConditionalSetRemoveAnswer): string => {
			switch (a.outcome) {
				case "removed":
					return a.generation;
				case "missing":
				case "conflict":
					return a.outcome;
				default:
					return a satisfies never;
			}
		};
		expectTypeOf(replace).returns.toEqualTypeOf<string>();
		expectTypeOf(setRemove).returns.toEqualTypeOf<string>();
	});
});
