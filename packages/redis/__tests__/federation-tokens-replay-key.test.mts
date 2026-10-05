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

	// A record key is `${prefix}${sid}:${name}`; `removeBySid`'s migration scan
	// sweeps `${prefix}${sid}:*`, which a replay key must never match.
	it.each([
		["ft:", "sid-1", "google"],
		["ft:", "c2lkLTE", "okta-prod"],
		["{ft}:", "sid-1", "google"],
		["app:{ft}:", "sid-1", "google"],
		["ft:", "{sid}", "google"],
		["ft:", "sid", "{google}"],
		["ft:", "sid{1", "google"],
	])(
		"keeps the record's slot, outside its session's scan, under the prefix %s (sid %s, name %s)",
		(prefix, sid, name) => {
			const key = `${prefix}${sid}:${name}`;
			const replay = replayKeyOf(key, prefix, "w-1");
			if (replay === null) throw new Error("refused");
			expect(slotOf(replay)).toBe(slotOf(key));
			expect(replay.startsWith(`${prefix}w:{`)).toBe(true);
			expect(replay.startsWith(`${prefix}${sid}:`)).toBe(false);
			expect(replayKeyOf(key, prefix, "w-2")).not.toBe(replay);
		},
	);

	it.each([
		["ft:", "sid-1", "go}ogle"],
		["ft:", "sid}1", "google"],
		["ft:", "sid{}1", "go}ogle"],
		["ft:", "a{}b", "google"],
	])(
		"answers null for a key whose braces leave no tag a replay key can carry (prefix %s, sid %s, name %s)",
		(prefix, sid, name) => {
			expect(replayKeyOf(`${prefix}${sid}:${name}`, prefix, "w-1")).toBeNull();
		},
	);
});

describe("the Redis store hands each attach, versioned read and conditional write a replay key of its own, on its record's slot", () => {
	const tokens: FederationTokens = {
		accessToken: "at",
		refreshToken: "rt",
		idToken: undefined,
		expiresAt: null,
		tokenType: undefined,
		scope: undefined,
		grantedScope: undefined,
		obtainedAt: undefined,
	};

	it("for an attach, a versioned read, a replace and a removal", async () => {
		const attachRecord = vi.fn(async () => "attached" as const);
		const readVersioned = vi.fn(async () => null);
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
			readVersioned,
			attachRecord,
			replaceIfGeneration,
			removeIfGeneration,
			pExpireGT: async () => {},
			durability: async () => ({
				maxmemoryPolicy: "noeviction",
				appendOnly: true,
				snapshots: undefined,
				refusal: undefined,
			}),
		} as unknown as FederationTokenStoreClient;
		const store = createRedisFederationTokenStore({
			deploymentMode: "unset",
			client,
			encryption: { mode: "allow-plaintext" },
		});
		const expected = "00000000-0000-4000-8000-000000000000" as Parameters<
			typeof store.replaceIf
		>[2];
		await store.attach("sid-1", "google", tokens);
		await store.attach("sid-1", "google", tokens);
		await store.getVersioned("sid-1", "google");
		await store.getVersioned("sid-1", "google");
		await store.replaceIf("sid-1", "google", expected, tokens);
		await store.replaceIf("sid-1", "google", expected, tokens);
		await store.removeIf("sid-1", "google", expected);
		await store.removeIf("sid-1", "google", expected);
		const keys = [
			...attachRecord.mock.calls.map((call) => (call as unknown[])[1]),
			...readVersioned.mock.calls.map((call) => (call as unknown[])[1]),
			...replaceIfGeneration.mock.calls.map((call) => (call as unknown[])[1]),
			...removeIfGeneration.mock.calls.map((call) => (call as unknown[])[1]),
		].map((input) => (input as { replayKey: string }).replayKey);
		expect(new Set(keys).size).toBe(8);
		for (const replayKey of keys) {
			expect(replayKey.startsWith("ft:w:{")).toBe(true);
			expect(slotOf(replayKey)).toBe(slotOf("ft:sid-1:google"));
		}
	});

	it.each([
		["sid-1", "go}ogle"],
		["sid}1", "google"],
	])(
		"refuses an attach, a versioned read, a replace and a removal of a record whose key no replay key can share a slot with, before any command (sid %s, name %s)",
		async (sid, name) => {
			const calls: string[] = [];
			const client = new Proxy(
				{},
				{
					get: (_target, method: string) => {
						if (method === "then") return undefined;
						return (..._args: unknown[]) => {
							calls.push(method);
							throw new Error(`${method} must not run`);
						};
					},
				},
			) as FederationTokenStoreClient;
			const store = createRedisFederationTokenStore({
				deploymentMode: "unset",
				client,
				encryption: { mode: "allow-plaintext" },
			});
			const expected = "00000000-0000-4000-8000-000000000000" as Parameters<
				typeof store.replaceIf
			>[2];
			await expect(store.attach(sid, name, tokens)).rejects.toThrow(
				new RangeError(
					"FederationTokenStore (redis): attach refused: no replay key can share the record's Redis Cluster slot (its key holds a brace but no hash tag)",
				),
			);
			await expect(store.getVersioned(sid, name)).rejects.toThrow(
				new RangeError(
					"FederationTokenStore (redis): getVersioned refused: no replay key can share the record's Redis Cluster slot (its key holds a brace but no hash tag)",
				),
			);
			await expect(store.replaceIf(sid, name, expected, tokens)).rejects.toThrow(
				new RangeError(
					"FederationTokenStore (redis): replaceIf refused: no replay key can share the record's Redis Cluster slot (its key holds a brace but no hash tag)",
				),
			);
			await expect(store.removeIf(sid, name, expected)).rejects.toThrow(
				new RangeError(
					"FederationTokenStore (redis): removeIf refused: no replay key can share the record's Redis Cluster slot (its key holds a brace but no hash tag)",
				),
			);
			expect(calls).toEqual([]);
		},
	);
});
