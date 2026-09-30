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
 * The session package's `loginEntry`: the deployment's login page
 * (`endpoints.login.url`) and the `redirect_to` protocol by which `/authorize`
 * and the federation-grants connect flow send a browser to it. It holds the
 * page to the rules `/authorize`'s own login redirect keeps (oauth's
 * configSchema and `loginRedirect`). With no login page configured it is
 * still built, so a composition that installs a consumer and never sends a
 * browser to log in boots; it fails where the page is read, naming the key.
 */

import {
	type AppConfig,
	defineModule,
	type FederationTokenStore,
	type LoginEntry,
	type SessionFederationIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestCsrfTokenSigner,
	loginEntryContract,
	makeValidAppConfig,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { createLoginEntry, loginEntryFromConfig } from "#/login-entry.mjs";
import { sessionModule } from "#/module.mjs";

describe("createLoginEntry keeps core's loginEntry contract", () => {
	it.each(loginEntryContract({ build: (url) => createLoginEntry(url) }))(
		"$name",
		async ({ run }) => {
			await run();
		},
	);

	it("joins redirect_to as /authorize and the connect flow joined it by hand", () => {
		expect(createLoginEntry("/login").urlFor("https://idp.example/oauth/authorize?a=1&b=2")).toBe(
			"/login?redirect_to=https%3A%2F%2Fidp.example%2Foauth%2Fauthorize%3Fa%3D1%26b%3D2",
		);
		expect(createLoginEntry("/login?tenant=x").urlFor("/back")).toBe(
			"/login?tenant=x&redirect_to=%2Fback",
		);
	});

	it.each([
		["a path", "/login?redirect_to=https://x"],
		["an absolute URL", "https://login.example/signin?tenant=x&redirect_to=https%3A%2F%2Fx"],
		["a name written percent-encoded", "/login?redirect%5Fto=x"],
		["a name with no value", "/login?tenant=x&redirect_to"],
		["a URL that does not parse", "http://[::1/login?redirect_to=x"],
		["a URL that does not parse, with a fragment", "http://[::1/login?tenant=x&redirect_to=y#z"],
	])("refuses %s whose own query carries redirect_to: urlFor adds it", (_label, page) => {
		expect(() => createLoginEntry(page)).toThrow(
			/must not carry a "redirect_to" query parameter of its own/,
		);
	});

	it.each([
		["redirect_to inside the fragment alone", "/login#redirect_to=https://x"],
		["a `?` inside the fragment alone", "/login#a?redirect_to=x"],
		["a name that differs in case", "/login?Redirect_To=x"],
		["a longer name", "/login?redirect_to_after=x"],
	])("builds an entry for a page with %s", (_label, page) => {
		expect(createLoginEntry(page).url).toBe(page);
	});

	it.each([
		["/login#x", "/login?redirect_to=%2Fback#x"],
		["/login?tenant=x#y", "/login?tenant=x&redirect_to=%2Fback#y"],
		["/login#a?b", "/login?redirect_to=%2Fback#a?b"],
		[
			"https://login.example/signin?tenant=x#y",
			"https://login.example/signin?tenant=x&redirect_to=%2Fback#y",
		],
	])("adds redirect_to to %s's query, before its fragment", (page, sent) => {
		expect(createLoginEntry(page).urlFor("/back")).toBe(sent);
	});
});

describe("loginEntryFromConfig", () => {
	it("answers the configured endpoints.login.url", () => {
		const entry = loginEntryFromConfig(makeValidAppConfig());
		expect(entry.url).toBe("/login");
		expect(entry.urlFor("/back")).toBe("/login?redirect_to=%2Fback");
	});

	it.each([
		["absent", {}],
		["empty", { login: { url: "" } }],
	])(
		"is built when endpoints.login.url is %s, and fails where the page is read, naming the key",
		(_what, endpoints) => {
			const entry = loginEntryFromConfig({ ...makeValidAppConfig(), endpoints });
			expect(Object.isFrozen(entry)).toBe(true);
			expect(() => entry.url).toThrow(/endpoints\.login\.url/);
			expect(() => entry.urlFor("/back")).toThrow(/endpoints\.login\.url/);
		},
	);
});

// ---------------------------------------------------------------------------
// The session module provides it
// ---------------------------------------------------------------------------

const providing = <T,>(name: string, slot: string, value: T) =>
	defineModule({ name, provides: { [slot]: () => value } as never });

const stores = [
	providing("test:user-repository", "userRepository", {
		authenticate: async () => null,
		authenticateByToken: async () => null,
	} as unknown as UserRepository),
	providing("test:user-session-store", "userSessionStore", {
		kind: "memory",
		async create() {},
		async get() {
			return null;
		},
		async delete() {},
	} as unknown as UserSessionStore),
	providing("test:federation-token-store", "federationTokenStore", {
		kind: "memory",
		async attach() {},
		async get() {
			return null;
		},
		async update() {},
		async removeBySid() {},
		async delete() {},
	} as unknown as FederationTokenStore),
	providing("test:session-federation-index", "sessionFederationIndex", {
		kind: "memory",
		async addFederation() {},
		async listFederations() {
			return [];
		},
		async removeFederation() {},
		async removeBySid() {},
	} as unknown as SessionFederationIndex),
	// Where the session store's module is loaded, it provides this.
	providing("test:csrf-token-signer", "csrfTokenSigner", createTestCsrfTokenSigner()),
];

/** A module that requires the entry and keeps what it was handed. */
const probe = (seen: { entry?: LoginEntry }) =>
	defineModule({
		name: "test:login-entry-consumer",
		requires: ["loginEntry"],
		contributes: {
			routes: [
				(deps) => {
					seen.entry = deps.loginEntry;
					return { id: "test:probe", mountPath: "/probe", handler: express.Router() };
				},
			],
		},
	});

const handles: { dispose(): Promise<void> }[] = [];
afterEach(async () => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
});

const boot = async (config: AppConfig, seen: { entry?: LoginEntry }) => {
	const handle = await createTestApp({
		modules: [sessionModule, ...stores, probe(seen)],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	handles.push(handle);
};

describe("the session module provides loginEntry", () => {
	it("hands a module that requires it the configured login page", async () => {
		const seen: { entry?: LoginEntry } = {};
		const base = makeValidAppConfig();
		await boot({ ...base, endpoints: { login: { url: "/sign-in?tenant=a" } } } as AppConfig, seen);
		expect(seen.entry?.url).toBe("/sign-in?tenant=a");
		expect(seen.entry?.urlFor("/back")).toBe("/sign-in?tenant=a&redirect_to=%2Fback");
	});

	it("boots with no login page configured: the entry fails only where it is read", async () => {
		const seen: { entry?: LoginEntry } = {};
		const base = makeValidAppConfig();
		// Core's schema takes any string here, the empty one included.
		await boot({ ...base, endpoints: { login: { url: "" } } } as AppConfig, seen);
		expect(seen.entry).toBeDefined();
		expect(() => seen.entry?.url).toThrow(/endpoints\.login\.url/);
	});
});
