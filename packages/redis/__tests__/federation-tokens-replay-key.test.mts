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

// A conditional write's replay key shares its record's Redis Cluster slot, so
// its script touches one slot; and every write names a replay key of its own.

import type { FederationTokens } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import type { FederationTokenStoreClient } from "#/clients.mjs";
import { createRedisFederationTokenStore } from "#/federation-tokens.mjs";
import { replayKeyOf } from "#/internal/replay-key.mjs";

/** Redis Cluster's CRC16 (XMODEM) of `text`, as `CLUSTER KEYSLOT` hashes it. */
const crc16 = (bytes: Buffer): number => {
	let crc = 0;
	for (const byte of bytes) {
		crc ^= byte << 8;
		for (let i = 0; i < 8; i += 1) {
			crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
		}
	}
	return crc;
};

/** The Cluster slot of `key`: its first non-empty hash tag's, else the whole key's. */
const slotOf = (key: string): number => {
	const open = key.indexOf("{");
	if (open !== -1) {
		const close = key.indexOf("}", open + 1);
		if (close > open + 1) return crc16(Buffer.from(key.slice(open + 1, close))) % 16384;
	}
	return crc16(Buffer.from(key)) % 16384;
};

describe("replayKeyOf", () => {
	it("hashes as Redis does", () => {
		// The documented example: both keys share the tag "user1000".
		expect(slotOf("{user1000}.following")).toBe(slotOf("{user1000}.followers"));
		expect(slotOf("123456789")).toBe(crc16(Buffer.from("123456789")) % 16384);
		expect(crc16(Buffer.from("123456789"))).toBe(0x31c3);
	});

	it.each([
		["ft:", "ft:sid-1:google"],
		["ft:", "ft:c2lkLTE:okta-prod"],
		["{ft}:", "{ft}:sid-1:google"],
		["app:{ft}:", "app:{ft}:sid-1:google"],
		["ft:", "ft:{sid}:google"],
		["ft:", "ft:sid{1:google"],
	])("keeps the record's slot under the prefix %s (%s)", (prefix, key) => {
		const replay = replayKeyOf(key, prefix, "w-1");
		expect(slotOf(replay)).toBe(slotOf(key));
		expect(replay.startsWith(prefix)).toBe(true);
		expect(replay).not.toBe(key);
		expect(replayKeyOf(key, prefix, "w-2")).not.toBe(replay);
	});
});

describe("the Redis store hands each conditional write a replay key of its own, on its record's slot", () => {
	const tokens: FederationTokens = {
		accessToken: "at",
		refreshToken: "rt",
		idToken: undefined,
		expiresAt: null,
		tokenType: undefined,
		scope: undefined,
		grantedScope: undefined,
	};

	it("for a replace and a removal", async () => {
		const replaceIfGeneration = vi.fn(async () => "conflict" as const);
		const removeIfGeneration = vi.fn(async () => "conflict" as const);
		const client = {
			get: async () => null,
			set: async () => "OK",
			del: async () => 0,
			unlink: async () => 0,
			sAddWithTtl: async () => {},
			sRem: async () => 0,
			sScanIterator: async function* () {},
			scanIterator: async function* () {},
			compareAndDelete: async () => false,
			readVersioned: async () => null,
			replaceIfGeneration,
			removeIfGeneration,
			pExpireGT: async () => {},
		} as unknown as FederationTokenStoreClient;
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client,
			encryption: { mode: "allow-plaintext" },
		});
		const expected = "00000000-0000-4000-8000-000000000000" as Parameters<
			typeof store.replaceIf
		>[2];
		await store.replaceIf("sid-1", "google", expected, tokens);
		await store.replaceIf("sid-1", "google", expected, tokens);
		await store.removeIf("sid-1", "google", expected);
		await store.removeIf("sid-1", "google", expected);
		const keys = [
			...replaceIfGeneration.mock.calls.map((call) => (call as unknown[])[1]),
			...removeIfGeneration.mock.calls.map((call) => (call as unknown[])[1]),
		].map((input) => (input as { replayKey: string }).replayKey);
		expect(new Set(keys).size).toBe(4);
		for (const replayKey of keys) {
			expect(replayKey.startsWith("ft:")).toBe(true);
			expect(slotOf(replayKey)).toBe(slotOf("ft:sid-1:google"));
		}
	});
});
