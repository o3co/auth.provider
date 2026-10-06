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
import { describe, expect, it } from "vitest";
import type { MfaTransactionStore } from "#/mfa/transactionStore.mjs";

/**
 * The `MfaTransactionStore` contract for what a note of a subject's
 * first-binding mark answers (the MFA ADR's D12), for every adapter: the
 * mark that stood before the note, read and replaced in one atomic step, so
 * a caller whose sign-in that earlier mark distrusts can refuse to bind
 * even when the earlier mark landed after its own read.
 *
 * A mark ends on the store's own clock, read through
 * {@link MfaFirstBindingNoteExpiryClock}.
 */
export type MfaFirstBindingNoteContractFactory = () => Promise<MfaTransactionStore>;

/** How a test reaches a mark's end on the store's own terms. */
export interface MfaFirstBindingNoteExpiryClock {
	/** Epoch milliseconds on the clock the store ends a mark by. */
	now(): Promise<number>;
	/** Resolves once the store has let everything ending at `at` go. */
	passed(at: number): Promise<void>;
}

const hostExpiry: MfaFirstBindingNoteExpiryClock = {
	now: async () => Date.now(),
	passed: async (at) => {
		while (Date.now() <= at) {
			await new Promise((r) => setTimeout(r, at - Date.now() + 1));
		}
	},
};

const MINUTE = 60_000;

export function runMfaFirstBindingNoteContract(
	factory: MfaFirstBindingNoteContractFactory,
	options: { readonly expiry?: MfaFirstBindingNoteExpiryClock } = {},
): void {
	const expiry = options.expiry ?? hostExpiry;

	/** A whole millisecond at or after both clocks: the host's, which a write is checked against, and the store's. */
	const nowOnBoth = async (): Promise<number> =>
		Math.floor(Math.max(Date.now(), await expiry.now()));

	describe("MfaTransactionStore contract: what a note of the first-binding mark answers", () => {
		it("answers null when no mark stood before it", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			expect(await store.noteFirstBinding("user-1", now, now + 10 * MINUTE)).toBeNull();
			expect(await store.firstBindingAt("user-1", now)).toBe(now);
		});

		it("answers the time of the mark that stood before it, and keeps the later of the two", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			expect(await store.noteFirstBinding("user-1", now - MINUTE, now + 10 * MINUTE)).toBeNull();
			expect(await store.noteFirstBinding("user-1", now, now + 10 * MINUTE)).toBe(now - MINUTE);
			expect(await store.firstBindingAt("user-1", now)).toBe(now);
			// An earlier note landing after a later one is answered the later, held mark.
			expect(await store.noteFirstBinding("user-1", now - 2 * MINUTE, now + 10 * MINUTE)).toBe(now);
			expect(await store.firstBindingAt("user-1", now)).toBe(now);
		});

		it("answers the earlier mark to a note made after a note that landed late: the earlier mark is not lost to it", async () => {
			// A first note is not answered in time and lands after another
			// writer read no mark; that writer's own note reports it.
			const store = await factory();
			const now = await nowOnBoth();
			expect(await store.firstBindingAt("user-1", now)).toBeNull();
			await store.noteFirstBinding("user-1", now - MINUTE, now + 10 * MINUTE);
			expect(await store.noteFirstBinding("user-1", now, now + 10 * MINUTE)).toBe(now - MINUTE);
		});

		it("answers null when the mark that stood has ended on the store's clock", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.noteFirstBinding("user-1", now - MINUTE, now + 1_000);
			await expiry.passed(now + 1_000);
			const later = await nowOnBoth();
			expect(await store.noteFirstBinding("user-1", later, later + 10 * MINUTE)).toBeNull();
		});

		it("answers each subject's own mark", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.noteFirstBinding("user-2", now - MINUTE, now + 10 * MINUTE);
			expect(await store.noteFirstBinding("user-1", now, now + 10 * MINUTE)).toBeNull();
		});

		it("answers null to exactly one of N notes in flight: each reads and replaces the mark in one step", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			const answers = await Promise.all(
				Array.from({ length: 10 }, (_, i) =>
					store.noteFirstBinding("user-1", now - i * 1_000, now + 10 * MINUTE),
				),
			);
			expect(answers.filter((answer) => answer === null)).toHaveLength(1);
			for (const answer of answers.filter((a) => a !== null)) {
				expect(answer).toEqual(expect.any(Number));
			}
			expect(await store.firstBindingAt("user-1", now)).toBe(now);
		});
	});
}
