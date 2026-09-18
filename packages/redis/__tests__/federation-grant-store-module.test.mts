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

// What turns the `federationGrants` configuration block into a Redis grant
// store (#593, D16, slice 4).
//
// Slice 3 built the adapter and left it taking options; nothing read HOCON. So
// this is where seconds become milliseconds, base64 becomes key material, and
// a configuration that cannot seal is refused at boot rather than at the first
// grant — which would mean refusing after a user had already consented.

import { describe, expect, it, vi } from "vitest";
import type { FederationGrantStoreClient } from "../src/clients.mjs";
import {
	DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS,
	redisFederationGrantStoreModuleFor,
	resolveRedisFederationGrantStoreOptions,
} from "../src/federation-grant-store.mjs";

const client = {} as FederationGrantStoreClient;

const KEY = Buffer.alloc(32, 7).toString("base64");

const config = (
	federationGrants: Record<string, unknown>,
	deployment?: Record<string, unknown>,
) => ({
	federationGrants,
	...(deployment ? { deployment } : {}),
});

/** What the module's `provides.federationGrantStore` is handed. */
const build = (
	federationGrants: Record<string, unknown>,
	options: Record<string, unknown> = {},
	deployment?: Record<string, unknown>,
) => {
	const module = redisFederationGrantStoreModuleFor(options as never);
	const provide = module.provides?.federationGrantStore as (deps: unknown) => unknown;
	return provide({
		federationGrantStoreClient: client,
		config: config(federationGrants, deployment),
	});
};

describe("the Redis federation grant store module (#593, D16)", () => {
	it("needs the client and the configuration, and says which slot it fills", () => {
		const module = redisFederationGrantStoreModuleFor();
		expect(module.name).toBe("redis-federation-grant-store");
		expect(module.requires).toStrictEqual(["federationGrantStoreClient", "config"]);
		expect(Object.keys(module.provides ?? {})).toStrictEqual(["federationGrantStore"]);
	});

	it("builds a store from a ring given in base64, and answers as a redis one", () => {
		const store = build({
			encryptionMode: "required",
			encryptionKeys: [{ id: "k-2026-09", key: KEY }],
		}) as { kind: string };
		expect(store.kind).toBe("redis");
	});

	it("turns the configured seconds into the milliseconds the adapter takes", () => {
		// The block is in seconds, as every duration an operator writes here is;
		// the adapter's option is in milliseconds, as every one it takes is. A
		// module that forwarded the number unchanged would keep a tombstone for
		// thirty seconds instead of thirty days.
		const resolved = resolveRedisFederationGrantStoreOptions(
			config({ encryptionKeys: [{ id: "k", key: KEY }], tombstoneRetention: 60 }) as never,
			{},
		);
		expect(resolved.tombstoneRetentionMs).toBe(60_000);
		// Zero is a deployment that keeps no tombstones, and is not "unset".
		expect(
			resolveRedisFederationGrantStoreOptions(
				config({ encryptionKeys: [{ id: "k", key: KEY }], tombstoneRetention: 0 }) as never,
				{},
			).tombstoneRetentionMs,
		).toBe(0);
		// The ring arrives as key material, in the order it was written.
		expect(resolved.encryption).toMatchObject({ mode: "required" });
		expect(resolved.encryption.mode === "required" && resolved.encryption.keys[0]?.key.length).toBe(
			32,
		);
	});

	it("refuses a ring it cannot seal with, at boot", () => {
		// The adapter refuses at construction (slice 3) rather than at the first
		// write; the module's part is not to hide that behind a default.
		expect(() => build({ encryptionMode: "required", encryptionKeys: [] })).toThrow(
			/encryption key/i,
		);
		expect(() => build({ encryptionMode: "required" })).toThrow(/encryption key/i);
		expect(() =>
			build({
				encryptionMode: "required",
				encryptionKeys: [{ id: "k", key: Buffer.alloc(16, 1).toString("base64") }],
			}),
		).toThrow(/32 bytes/);
		expect(() =>
			build({ encryptionMode: "required", encryptionKeys: [{ id: "k", key: "not base64!!" }] }),
		).toThrow();
	});

	it("refuses two keys under one id, and keeps the order the ring was written in", () => {
		expect(() =>
			build({
				encryptionKeys: [
					{ id: "k", key: KEY },
					{ id: "k", key: Buffer.alloc(32, 8).toString("base64") },
				],
			}),
		).toThrow(/id/i);
	});

	it("refuses plaintext where the federation token store refuses it, in the same words", () => {
		// One escape hatch and not two: the message names which store refused.
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			expect(() =>
				build({ encryptionMode: "allow-plaintext" }, { environment: "production" }),
			).toThrow(/\[federation-grants\] mode "allow-plaintext" is refused/);
			expect(() => build({ encryptionMode: "allow-plaintext" }, {}, { mode: "multi" })).toThrow(
				/\[federation-grants\]/,
			);
			// And in development it warns rather than refusing.
			expect(() => build({ encryptionMode: "allow-plaintext" })).not.toThrow();
		} finally {
			warn.mockRestore();
		}
	});

	it("leaves the key prefix and the listing allowance to their own section", () => {
		// They are adapter layout rather than grant policy, as the other stores'
		// prefixes are: `redisFederationGrantStore`, beside them.
		const resolved = resolveRedisFederationGrantStoreOptions(
			{
				federationGrants: { encryptionKeys: [{ id: "k", key: KEY }] },
				redisFederationGrantStore: { keyPrefix: "t:", listingAllowanceMs: 1_000 },
			} as never,
			{},
		);
		expect(resolved.keyPrefix).toBe("t:");
		expect(resolved.listingAllowanceMs).toBe(1_000);
		// Unset, the module passes nothing and the adapter's own default applies:
		// one default, in one place, rather than a copy here to drift from it.
		const defaults = resolveRedisFederationGrantStoreOptions(
			config({ encryptionKeys: [{ id: "k", key: KEY }] }) as never,
			{},
		);
		expect(defaults.keyPrefix).toBe("fg:");
		expect(defaults).not.toHaveProperty("listingAllowanceMs");
		expect(defaults).not.toHaveProperty("tombstoneRetentionMs");
		expect(DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS).toBe(300_000);
	});
});
