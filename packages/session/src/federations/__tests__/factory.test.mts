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

import { AdapterFactoryError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	createFederationProviderFactory,
	registerBuiltinFederations,
} from "#/federations/factory.mjs";

describe("createFederationProviderFactory", () => {
	it("returns an AdapterFactory with no registered types", () => {
		const factory = createFederationProviderFactory();
		expect(factory.registeredTypes()).toEqual([]);
	});

	it("rejects factory.create() for unknown type with AdapterFactoryError { reason: 'unknown', kind: 'FederationProvider' }", async () => {
		const factory = createFederationProviderFactory();
		await expect(factory.create({ type: "google", name: "google" })).rejects.toSatisfy(
			(err) =>
				err instanceof AdapterFactoryError &&
				err.reason === "unknown" &&
				err.kind === "FederationProvider",
		);
	});
});

describe("registerBuiltinFederations", () => {
	it("registers 'google' and 'github' types", () => {
		const factory = createFederationProviderFactory();
		registerBuiltinFederations(factory);
		expect(factory.registeredTypes()).toEqual(expect.arrayContaining(["google", "github"]));
	});

	it("builds a Google provider via factory.create({ type: 'google', name, clientId, ... })", async () => {
		const factory = createFederationProviderFactory();
		registerBuiltinFederations(factory);
		const provider = await factory.create({
			type: "google",
			name: "google",
			clientId: "id",
			clientSecret: "secret",
			callbackURL: "https://example.com/cb",
		});
		expect(provider.name).toBe("google");
		expect(provider.scope).toContain("email");
	});

	it("builds a GitHub provider via factory.create({ type: 'github', name, ... })", async () => {
		const factory = createFederationProviderFactory();
		registerBuiltinFederations(factory);
		const provider = await factory.create({
			type: "github",
			name: "github",
			clientId: "id",
			clientSecret: "secret",
			callbackURL: "https://example.com/cb",
		});
		expect(provider.name).toBe("github");
		expect(provider.scope).toEqual(["read:user", "user:email"]);
	});

	it("supports multi-tenant instance names (e.g. 'google-work' with type='google')", async () => {
		const factory = createFederationProviderFactory();
		registerBuiltinFederations(factory);
		const provider = await factory.create({
			type: "google",
			name: "google-work",
			clientId: "id",
			clientSecret: "secret",
			callbackURL: "https://example.com/cb",
		});
		expect(provider.name).toBe("google-work");
	});

	it("throws when required fields are missing (google)", async () => {
		const factory = createFederationProviderFactory();
		registerBuiltinFederations(factory);
		await expect(
			factory.create({
				type: "google",
				name: "google",
				// missing clientId, clientSecret, callbackURL
			}),
		).rejects.toThrow(/clientId|clientSecret|callbackURL/i);
	});

	it("throws when required fields are missing (github)", async () => {
		const factory = createFederationProviderFactory();
		registerBuiltinFederations(factory);
		await expect(
			factory.create({
				type: "github",
				name: "github",
			}),
		).rejects.toThrow(/clientId|clientSecret|callbackURL/i);
	});
});

describe("FederationProviderBase assignability", () => {
	it("typed element is FederationProviderBase", async () => {
		const { createFederationProviderFactory } = await import("#/federations/factory.mjs");
		const factory = createFederationProviderFactory();
		// If `create`'s return type is Promise<FederationProviderBase>, this local variable
		// typed as FederationProviderBase is trivially assignable.
		factory.register("stub", async () => ({
			name: "stub",
			scope: [],
			validateRedirect: () => ({ ok: true, value: undefined }),
			resolveCallbackRedirect: () => ({ ok: true, value: "/" }),
			async setupPassportStrategy() {},
		}));
		const base: import("#/federations/types.mjs").FederationProviderBase = await factory.create({
			type: "stub",
			name: "stub",
		});
		expect(base.name).toBe("stub");
	});
});
