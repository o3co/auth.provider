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

// What a client needs on its record to use a federation grant at all
// (#593, D9, slice 4).
//
// Two fields, and the reason they are two: the connection allowlist is what a
// worker needs to spend a grant that already exists, and the redirect URIs are
// what a browser needs to create one. A token/status worker never performs the
// browser flow, so requiring a redirect URI of it would couple the two.
//
// Absence means nothing is allowed, on both. A client registered before this
// existed must not find itself opted into offline delegation.

import { describe, expect, it } from "vitest";
import { InMemoryClientRepository } from "#/repositories/InMemoryClientRepository.mjs";

const base = {
	clientSecret: "s3cret-s3cret-s3cret-s3cret",
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedRedirectUris: ["https://app.example.test/cb"],
};

const repository = (over: Record<string, unknown> = {}) =>
	new InMemoryClientRepository(new Map([["worker", { ...base, ...over } as never]]));

describe("a client's federation grant fields (#593, D9)", () => {
	it("are absent by default, and absent means no connection and no return destination", async () => {
		const found = await repository().findById("worker");
		expect(found?.allowedFederationGrantConnections).toBeUndefined();
		expect(found?.federationGrantRedirectUris).toBeUndefined();
	});

	it("reach both projections: what a route reads after authenticating is what registration declared", async () => {
		// `findById` and `authenticate` project separately, and a field added to
		// one and not the other reads as absent exactly where it is used.
		const store = repository({
			allowedFederationGrantConnections: ["graph", "calendar"],
			federationGrantRedirectUris: ["https://app.example.test/grants/cb"],
		});
		for (const client of [
			await store.findById("worker"),
			await store.authenticate("worker", "s3cret-s3cret-s3cret-s3cret"),
		]) {
			expect(client?.allowedFederationGrantConnections).toStrictEqual(["graph", "calendar"]);
			expect(client?.federationGrantRedirectUris).toStrictEqual([
				"https://app.example.test/grants/cb",
			]);
		}
	});

	it("keep the order and the exact spelling of the connection names", async () => {
		// A connection name is compared exactly against configuration: no
		// trimming, no case folding, no sorting.
		const names = ["Graph", "graph", "graph-2", "a_b"];
		const found = await repository({ allowedFederationGrantConnections: names }).findById("worker");
		expect(found?.allowedFederationGrantConnections).toStrictEqual(names);
	});

	it("refuse a duplicate, an empty name, and a value that is not a list of strings", async () => {
		for (const value of [["graph", "graph"], ["graph", ""], [" "], ["graph", 1], "graph", {}]) {
			expect(
				() => repository({ allowedFederationGrantConnections: value }),
				JSON.stringify(value),
			).toThrow();
		}
	});

	it("hold a return destination to the same rules as any other redirect URI, and never inherit one", async () => {
		for (const value of [
			["http://app.example.test/cb"],
			["https://app.example.test/cb#frag"],
			["not a uri"],
			["https://app.example.test/cb", "https://app.example.test/cb"],
			[""],
		]) {
			expect(
				() => repository({ federationGrantRedirectUris: value }),
				JSON.stringify(value),
			).toThrow();
		}
		// Loopback http is allowed, as it is for the ordinary allowlist.
		expect(() =>
			repository({ federationGrantRedirectUris: ["http://127.0.0.1:8080/cb"] }),
		).not.toThrow();
		// And the ordinary allowlist is not a return destination for a grant.
		const found = await repository().findById("worker");
		expect(found?.federationGrantRedirectUris).toBeUndefined();
		expect(found?.allowedRedirectUris).toStrictEqual(["https://app.example.test/cb"]);
	});

	it("cannot be registered by a public client: a grant is a confidential client's to hold", async () => {
		for (const field of ["allowedFederationGrantConnections", "federationGrantRedirectUris"]) {
			expect(
				() =>
					new InMemoryClientRepository(
						new Map([
							[
								"spa",
								{
									tokenEndpointAuthMethod: "none",
									allowedRedirectUris: ["https://app.example.test/cb"],
									[field]:
										field === "allowedFederationGrantConnections"
											? ["graph"]
											: ["https://app.example.test/grants/cb"],
								} as never,
							],
						]),
					),
				field,
			).toThrow(/public client|tokenEndpointAuthMethod/i);
		}
	});

	it("accept an empty list, which says the same as absence", async () => {
		const found = await repository({
			allowedFederationGrantConnections: [],
			federationGrantRedirectUris: [],
		}).findById("worker");
		expect(found?.allowedFederationGrantConnections).toStrictEqual([]);
		expect(found?.federationGrantRedirectUris).toStrictEqual([]);
	});
});
