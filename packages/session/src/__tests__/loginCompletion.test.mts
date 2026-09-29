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
 * The session package's `loginCompletion` (see ADR
 * 2026-09-28-session-admission): `establishSession` and `answerInterruption`
 * with what the provider holds — the session stores, the session's lifetime,
 * the CSRF guard — out of their arguments, as the slot a requirement's
 * completion (the MFA package's) requires instead of importing this package.
 * The login-completion module provides it, over the stores and the
 * `csrfGuard` it requires; the session module does not, since a provider
 * there could not read the `csrfGuard` slot its own module fills.
 */

import {
	type AppConfig,
	createInMemoryUserSessionStore,
	defineModule,
	type FederationTokenStore,
	type LoginCompletion,
	type SessionFederationIndex,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestCsrfGuard,
	loginCompletionContract,
	makeValidAppConfig,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createLoginCompletion } from "#/login-completion.mjs";
import { sessionModule } from "#/module.mjs";
import { loginCompletionModule } from "#/modules/loginCompletionModule.mjs";

/** A memory session store that counts the records it holds. */
const countingStore = (): { readonly store: UserSessionStore; readonly records: () => number } => {
	const inner = createInMemoryUserSessionStore();
	let held = 0;
	const store: UserSessionStore = {
		...inner,
		kind: inner.kind,
		create: async (input) => {
			await inner.create(input);
			held++;
		},
		get: (sid) => inner.get(sid),
		delete: async (sid) => {
			const before = await inner.get(sid);
			await inner.delete(sid);
			if (before !== null) held--;
		},
	};
	return { store, records: () => held };
};

/** A session store that is down. */
const downStore = (): UserSessionStore => ({
	...createInMemoryUserSessionStore(),
	create: async () => {
		throw new Error("connect ECONNREFUSED 127.0.0.1:6379");
	},
});

describe("createLoginCompletion keeps core's loginCompletion contract", () => {
	const guard = createTestCsrfGuard();
	let counted = countingStore();
	it.each(
		loginCompletionContract({
			build: () => {
				counted = countingStore();
				return createLoginCompletion({
					userSessionStore: counted.store,
					sessionTtlMs: 3_600_000,
					csrf: guard,
				});
			},
			withSessionStoreOutage: () => {
				counted = countingStore();
				return createLoginCompletion({
					userSessionStore: downStore(),
					sessionTtlMs: 3_600_000,
					csrf: guard,
				});
			},
			records: () => counted.records(),
			csrfCookieName: guard.cookieName,
		}),
	)("$name", async ({ run }) => {
		await run();
	});

	it("is frozen", () => {
		expect(
			Object.isFrozen(
				createLoginCompletion({ userSessionStore: counted.store, sessionTtlMs: 1, csrf: guard }),
			),
		).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// The login-completion module provides it
// ---------------------------------------------------------------------------

const providing = <T,>(name: string, slot: string, value: T) =>
	defineModule({ name, provides: { [slot]: () => value } as never });

const moduleStore = countingStore();

const stores = [
	providing("test:user-repository", "userRepository", {
		authenticate: async () => null,
		authenticateByToken: async () => null,
	} as unknown as UserRepository),
	providing("test:user-session-store", "userSessionStore", moduleStore.store),
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
];

/** A module that hands the test the `loginCompletion` it requires. */
const consumer = (seen: { completion?: LoginCompletion }) =>
	defineModule({
		name: "test:login-completion-consumer",
		requires: ["loginCompletion"],
		contributes: {
			routes: [
				(deps) => {
					seen.completion = deps.loginCompletion;
					return { id: "test:probe", mountPath: "/probe", handler: express.Router() };
				},
			],
		},
	});

const provided: { completion?: LoginCompletion } = {};
/** The same, with a CSRF guard of the composition's own in the session module's place. */
const substituted: { completion?: LoginCompletion } = {};
/** A guard whose token cookie no configuration-derived guard would set. */
const substitute = createTestCsrfGuard({
	sessionCookie: {
		name: "substitute.session",
		secure: true,
		sameSite: "lax",
		domain: undefined,
		maxAgeMs: 3_600_000,
	},
});
const disposers: (() => Promise<void>)[] = [];

beforeAll(async () => {
	const bootstrapComponents = {
		config: makeValidAppConfig() as AppConfig,
		pathResolver: (s: string) => s,
	};
	const handle = await createTestApp({
		modules: [sessionModule, loginCompletionModule, ...stores, consumer(provided)],
		bootstrapComponents,
	});
	disposers.push(() => handle.dispose());
	const overridden = await createTestApp({
		modules: [sessionModule, loginCompletionModule, ...stores, consumer(substituted)],
		bootstrapComponents,
		overrideComponents: { csrfGuard: substitute },
	});
	disposers.push(() => overridden.dispose());
});

afterAll(async () => {
	await Promise.all(disposers.splice(0).map((dispose) => dispose()));
});

describe("the login-completion module provides loginCompletion", () => {
	it("is frozen", () => {
		expect(provided.completion).toBeDefined();
		expect(Object.isFrozen(provided.completion)).toBe(true);
	});

	it("requires the csrfGuard slot and the session stores, and provides loginCompletion alone", () => {
		expect(loginCompletionModule.name).toBe("login-completion");
		expect(loginCompletionModule.requires).toEqual(
			expect.arrayContaining(["config", "userSessionStore", "csrfGuard"]),
		);
		expect(Object.keys(loginCompletionModule.provides ?? {})).toEqual(["loginCompletion"]);
	});

	it("is not the session module's: a provider there could not read the guard its own module fills", () => {
		expect(Object.keys(sessionModule.provides ?? {})).not.toContain("loginCompletion");
	});

	// Over the session store the module requires, and the token of the CSRF
	// guard the session module provides: the fixture's session cookie is
	// `__Host-auth.session`.
	it.each(
		loginCompletionContract({
			build: () => provided.completion as LoginCompletion,
			records: () => moduleStore.records(),
			csrfCookieName: "__Host-auth.session.csrf",
		}),
	)("$name", async ({ run }) => {
		await run();
	});
});

describe("the login-completion module answers with the deployment's csrfGuard, whoever filled it", () => {
	// The composition put its own guard in the slot: an interruption's fresh
	// token is that guard's — its cookie — so the page goes on posting to
	// routes that run the same guard.
	it.each(
		loginCompletionContract({
			build: () => substituted.completion as LoginCompletion,
			records: () => moduleStore.records(),
			csrfCookieName: substitute.cookieName,
		}),
	)("$name", async ({ run }) => {
		await run();
	});
});
