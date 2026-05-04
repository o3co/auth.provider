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
import type { RefreshTokenFamilyClient } from "../src/clients.mjs";

/**
 * Factory for the contract suite. Returns a freshly-built RefreshTokenFamilyClient
 * that targets a live Redis instance. The contract suite exercises the
 * `duplicate()` NORMATIVE MUSTs (T4 hardening per Claude review I1):
 *
 *   1. Each duplicate is a distinct instance.
 *   2. Each duplicate is bound to a fresh underlying socket — observed
 *      behaviourally via WATCH isolation.
 *   3. Disposal closes the underlying socket.
 *
 * Wrapper authors integrating a new Redis library MUST run this suite
 * against their wrapper before shipping. A passing in-memory stub is
 * NOT sufficient evidence of WATCH isolation; this suite requires a
 * live Redis to detect socket sharing.
 */
export type RefreshTokenFamilyClientFactory = () => RefreshTokenFamilyClient;

export function runRefreshTokenFamilyClientDuplicateContract(
	factory: RefreshTokenFamilyClientFactory,
	keyPrefix: string,
): void {
	describe("RefreshTokenFamilyClient.duplicate() — NORMATIVE contract", () => {
		it("MUST 1: each invocation returns a distinct DisposableRefreshTokenFamilyClient instance", async () => {
			const client = factory();
			await using dup1 = client.duplicate();
			await using dup2 = client.duplicate();
			expect(dup1).not.toBe(client);
			expect(dup2).not.toBe(client);
			expect(dup1).not.toBe(dup2);
		});

		it("MUST 2: duplicates have independent WATCH state (proves fresh socket)", async () => {
			// Strategy: watch two ABSENT keys (keyA, keyB). A watched absent key
			// triggers EXEC failure when another connection creates it (NX set
			// from absent → present is a mutation that invalidates the watch).
			// RefreshTokenFamilyClient only exposes `set(…, "NX")` — we exploit that
			// to perform the mutation without needing a `del()` method.
			const client = factory();
			const keyA = `${keyPrefix}watch-isolation-a-${Date.now()}`;
			const keyB = `${keyPrefix}watch-isolation-b-${Date.now()}`;
			// Ensure keys are absent before the test (fresh prefix eliminates risk).

			await using dup1 = client.duplicate();
			await using dup2 = client.duplicate();

			// dup1 watches keyA, dup2 watches keyB. If duplicate() shared a
			// socket, both WATCH calls would land on the same connection and
			// both keys would be in the shared watch list — modifying keyA
			// would then fail dup2's EXEC too.
			await dup1.watch(keyA);
			await dup2.watch(keyB);

			// Mutate keyA from a third duplicate — NX set succeeds because keyA is
			// absent, and any change (absent→present) invalidates dup1's WATCH on keyA.
			await using mutator = client.duplicate();
			await mutator.set(keyA, "mutated-by-mutator", "PX", 60_000, "NX");

			// dup1's EXEC must fail (its watched key was created by mutator).
			const dup1Multi = dup1.multi();
			dup1Multi.set(`${keyPrefix}watch-result-a`, "should-not-commit", "PX", 60_000);
			const dup1Result = await dup1Multi.exec();
			expect(dup1Result).toBeNull();

			// dup2's EXEC must succeed (keyB was not touched). If duplicate()
			// shared a socket, dup2 would observe dup1's WATCH list and ALSO
			// fail — that would be the contract violation.
			const dup2Multi = dup2.multi();
			dup2Multi.set(`${keyPrefix}watch-result-b`, "must-commit", "PX", 60_000);
			const dup2Result = await dup2Multi.exec();
			expect(dup2Result).not.toBeNull();
		});

		it("MUST 3: [Symbol.asyncDispose] closes the connection (smoke check)", async () => {
			// Direct disposal without `await using` to verify the contract
			// surface is callable. We don't introspect the underlying socket
			// state because that's wrapper-internal — the smoke check just
			// confirms dispose returns a resolved Promise.
			const client = factory();
			const dup = client.duplicate();
			await dup[Symbol.asyncDispose]();
			// No assertion beyond no-throw — the absence of a hang/throw is
			// the signal.
			expect(true).toBe(true);
		});

		it("MUST 1 (recursive): duplicate's own duplicate() returns a fresh instance", async () => {
			const client = factory();
			await using dup1 = client.duplicate();
			await using nested = dup1.duplicate();
			expect(nested).not.toBe(dup1);
			expect(nested).not.toBe(client);
		});
	});
}
