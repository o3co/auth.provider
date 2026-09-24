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

import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	type AssertionIssuerEntryInput,
	checkAssertionIssuerEntry,
	createMemoryAssertionIssuerRegistry,
} from "#/assertions/issuerRegistry.mjs";

/**
 * #525 — the trust registry's admin surface and entry validation. What an
 * entry means at verification time is pinned in
 * `registryAssertionVerifier.test.mts`; this file is about the list itself.
 */

const { publicKey } = generateKeyPairSync("ed25519");
const entry = (over: Partial<AssertionIssuerEntryInput> = {}): AssertionIssuerEntryInput => ({
	issuer: "https://devices.example",
	keys: { type: "key", key: publicKey },
	algorithms: ["EdDSA"],
	...over,
});

describe("createMemoryAssertionIssuerRegistry — the admin surface (#525)", () => {
	it("finds what was added, by exact issuer", async () => {
		const registry = createMemoryAssertionIssuerRegistry([entry()]);
		expect(await registry.findIssuer("https://devices.example")).toMatchObject({
			issuer: "https://devices.example",
		});
		// Never by prefix, suffix or case: an issuer is a string, matched whole.
		expect(await registry.findIssuer("https://devices.example/")).toBeNull();
		expect(await registry.findIssuer("https://DEVICES.example")).toBeNull();
		expect(await registry.findIssuer("https://other.example")).toBeNull();
	});

	it("adds, lists and removes", async () => {
		const registry = createMemoryAssertionIssuerRegistry();
		expect(await registry.list()).toEqual([]);
		await registry.add(entry());
		await registry.add(entry({ issuer: "https://second.example" }));
		expect((await registry.list()).map((e) => e.issuer)).toEqual([
			"https://devices.example",
			"https://second.example",
		]);
		expect(await registry.remove("https://devices.example")).toBe(true);
		expect(await registry.remove("https://devices.example")).toBe(false);
		expect(await registry.findIssuer("https://devices.example")).toBeNull();
	});

	it("refuses a duplicate issuer — entries are immutable, remove and re-add", async () => {
		const registry = createMemoryAssertionIssuerRegistry([entry()]);
		await expect(registry.add(entry({ algorithms: ["ES256"] }))).rejects.toThrow(
			/already registered/,
		);
		// The original stands.
		expect((await registry.findIssuer("https://devices.example"))?.algorithms).toEqual(["EdDSA"]);
	});

	it("lets expiresAt, and only expiresAt, change in place", async () => {
		const registry = createMemoryAssertionIssuerRegistry([entry()]);
		const until = new Date(Date.now() + 60_000);
		expect(await registry.setExpiresAt("https://devices.example", until)).toBe(true);
		expect((await registry.findIssuer("https://devices.example"))?.expiresAt).toBe(until);
		expect(await registry.setExpiresAt("https://devices.example", undefined)).toBe(true);
		expect((await registry.findIssuer("https://devices.example"))?.expiresAt).toBeUndefined();
		expect(await registry.setExpiresAt("https://nobody.example", until)).toBe(false);
	});

	it("still lists an expired entry — expiry is the verifier's refusal, not a deletion", async () => {
		const registry = createMemoryAssertionIssuerRegistry([
			entry({ expiresAt: new Date(Date.now() - 1) }),
		]);
		expect(await registry.list()).toHaveLength(1);
		expect(await registry.findIssuer("https://devices.example")).not.toBeNull();
	});

	it("answers with every field named, a ceiling the entry left out as undefined", async () => {
		// What a registry answers with is the stored form: a registry over a
		// store builds the same shape on read-back, where a key it forgot would
		// be a ceiling silently dropped — failing open.
		const registry = createMemoryAssertionIssuerRegistry([entry()]);
		const found = await registry.findIssuer("https://devices.example");

		expect(Object.keys(found ?? {}).sort()).toEqual(
			[
				"algorithms",
				"allowedAudiences",
				"allowedClients",
				"allowedScopes",
				"allowedSubjects",
				"clockToleranceSeconds",
				"expiresAt",
				"issuer",
				"keys",
				"profile",
			].sort(),
		);
		expect(found?.allowedClients).toBeUndefined();
		// And whole, against an entry written out here rather than the same
		// registry's other answer: a class instance, or a key too many, fails.
		// `list()` answers with the same shape.
		const whole = {
			issuer: "https://devices.example",
			keys: { type: "key", key: publicKey },
			algorithms: ["EdDSA"],
			allowedSubjects: undefined,
			allowedScopes: undefined,
			allowedAudiences: undefined,
			allowedClients: undefined,
			expiresAt: undefined,
			profile: undefined,
			clockToleranceSeconds: undefined,
		};
		expect(found).toStrictEqual(whole);
		expect(await registry.list()).toStrictEqual([whole]);
	});

	it("round-trips list() into add() on another registry", async () => {
		// The stored form is accepted back as input, so moving entries between
		// registries loses nothing.
		const from = createMemoryAssertionIssuerRegistry([
			entry({ allowedClients: ["client-a"], profile: "id-jag", clockToleranceSeconds: 5 }),
		]);
		const to = createMemoryAssertionIssuerRegistry();
		for (const listed of await from.list()) await to.add(listed);

		expect(await to.findIssuer("https://devices.example")).toStrictEqual(
			await from.findIssuer("https://devices.example"),
		);
	});

	it("refuses a reader function on the input, rather than normalising it away", async () => {
		// The normaliser copies the entry's own fields and nothing else. If the
		// check ran after it, a reader would be silently dropped instead of
		// refused — and refusing it is the point: an ignored handle reader hands
		// the Store a bare `sub` two issuers can share.
		const withReader = {
			...entry(),
			readSubjectHandle: () => "x",
		} as unknown as AssertionIssuerEntryInput;

		expect(() => createMemoryAssertionIssuerRegistry([withReader])).toThrow(/readSubjectHandle/);
		await expect(createMemoryAssertionIssuerRegistry().add(withReader)).rejects.toThrow(
			/readSubjectHandle/,
		);
	});

	it("clears expiresAt by value, and keeps the key", async () => {
		const registry = createMemoryAssertionIssuerRegistry([entry({ expiresAt: new Date() })]);
		await registry.setExpiresAt("https://devices.example", undefined);
		const found = await registry.findIssuer("https://devices.example");

		expect(found && "expiresAt" in found).toBe(true);
		expect(found?.expiresAt).toBeUndefined();
	});

	it("reports its kind", () => {
		expect(createMemoryAssertionIssuerRegistry().kind).toBe("memory");
	});
});

describe("checkAssertionIssuerEntry — what an entry must say (#525)", () => {
	it("requires an issuer and at least one algorithm", () => {
		expect(() => checkAssertionIssuerEntry(entry({ issuer: "" }))).toThrow(/issuer is required/);
		expect(() => checkAssertionIssuerEntry(entry({ algorithms: [] }))).toThrow(
			/at least one algorithm/,
		);
	});

	it("requires https for a JWKS endpoint, loopback excepted", () => {
		const jwks = (uri: string) => entry({ keys: { type: "jwks_uri", uri } });
		expect(() => checkAssertionIssuerEntry(jwks("http://idp.example/jwks"))).toThrow(
			/must be https/,
		);
		expect(() => checkAssertionIssuerEntry(jwks("https://idp.example/jwks"))).not.toThrow();
		expect(() => checkAssertionIssuerEntry(jwks("http://127.0.0.1:8080/jwks"))).not.toThrow();
		expect(() => checkAssertionIssuerEntry(jwks("http://localhost/jwks"))).not.toThrow();
		expect(() => checkAssertionIssuerEntry(jwks("not a url"))).toThrow(/not an absolute URL/);
	});

	it("is what the memory registry applies on add and at construction", async () => {
		expect(() => createMemoryAssertionIssuerRegistry([entry({ algorithms: [] })])).toThrow(
			/at least one algorithm/,
		);
		const registry = createMemoryAssertionIssuerRegistry();
		await expect(registry.add(entry({ issuer: "" }))).rejects.toThrow(/issuer is required/);
		expect(await registry.list()).toEqual([]);
	});
});
