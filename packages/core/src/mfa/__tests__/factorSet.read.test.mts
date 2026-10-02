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
 * `readMfaFactorSet`: what `MfaFactorStore.listVersioned` answered, read as
 * the port promises it, or a `TypeError` the caller answers as the store's
 * outage — never as a set with nothing in it.
 */

import { describe, expect, it } from "vitest";
import { type MfaFactorRecord, readMfaFactorSet } from "#/mfa/factorStore.mjs";

const G = "2b0d5c51-8a4b-4a0e-9a63-0f0c3c1f2f6e";

const record = (id: string, subject = "user-1"): MfaFactorRecord => ({
	id,
	subject,
	kind: "totp",
	label: undefined,
	binding: undefined,
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: undefined,
	version: 1,
	data: "v2.opaque",
});

describe("readMfaFactorSet", () => {
	it("reads a set never written, and a written one with its records, as a fresh answer", () => {
		expect(readMfaFactorSet({ generation: null, items: [] }, "user-1")).toStrictEqual({
			generation: null,
			items: [],
		});
		const items = [record("a"), record("b")];
		const read = readMfaFactorSet({ generation: G, items, extra: true }, "user-1");
		expect(read).toStrictEqual({ generation: G, items });
		expect(read.items).not.toBe(items);
		expect(Object.isFrozen(read)).toBe(true);
		expect(readMfaFactorSet({ generation: G, items: [] }, "user-1")).toStrictEqual({
			generation: G,
			items: [],
		});
	});

	it("throws a TypeError for an answer outside the promise", () => {
		for (const answer of [
			undefined,
			null,
			[],
			{ items: [] },
			{ generation: G },
			{ generation: undefined, items: [] },
			{ generation: "", items: [] },
			{ generation: 1, items: [] },
			{ generation: G, items: {} },
			// A set never written holds nothing.
			{ generation: null, items: [record("a")] },
			// Every record is the subject's, and no id is there twice.
			{ generation: G, items: [record("a", "user-2")] },
			{ generation: G, items: [record("a"), record("a")] },
			{ generation: G, items: [null] },
			{ generation: G, items: [{ ...record("a"), id: 7 }] },
		]) {
			expect(() => readMfaFactorSet(answer, "user-1"), JSON.stringify(answer)).toThrow(TypeError);
		}
	});

	it("throws a TypeError for an answer whose read throws, a record's included", () => {
		const answer = {
			get generation(): string {
				throw new RangeError("getter");
			},
			items: [],
		};
		expect(() => readMfaFactorSet(answer, "user-1")).toThrow(TypeError);
		const item = {
			...record("a"),
			get subject(): string {
				throw new RangeError("getter");
			},
		};
		expect(() => readMfaFactorSet({ generation: G, items: [item] }, "user-1")).toThrow(TypeError);
	});
});
