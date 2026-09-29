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
 * The session package's `loginCompletion` (#728; the session-admission
 * ADR's D5): `establishSession` and `answerInterruption` with what the
 * provider holds — the session stores, the session's lifetime, the CSRF
 * guard — out of their arguments, as the slot a requirement's completion
 * (the MFA package's) requires instead of importing this package.
 *
 * - `createLoginCompletion` keeps core's contract (`loginCompletionContract`)
 *   over a session store that answers and one that is down, with its
 *   records counted and the CSRF token's cookie named.
 * - The session module provides it, over the stores it requires and the
 *   CSRF guard it provides: the contract holds of the provided completion.
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
// The session module provides it
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

const provided: { completion?: LoginCompletion; dispose?: () => Promise<void> } = {};

beforeAll(async () => {
	const handle = await createTestApp({
		modules: [
			sessionModule,
			...stores,
			defineModule({
				name: "test:login-completion-consumer",
				requires: ["loginCompletion"],
				contributes: {
					routes: [
						(deps) => {
							provided.completion = deps.loginCompletion;
							return { id: "test:probe", mountPath: "/probe", handler: express.Router() };
						},
					],
				},
			}),
		],
		bootstrapComponents: {
			config: makeValidAppConfig() as AppConfig,
			pathResolver: (s: string) => s,
		},
	});
	provided.dispose = () => handle.dispose();
});

afterAll(async () => {
	await provided.dispose?.();
});

describe("the session module provides loginCompletion", () => {
	it("is frozen", () => {
		expect(provided.completion).toBeDefined();
		expect(Object.isFrozen(provided.completion)).toBe(true);
	});

	// Over the session store the module requires, and the token of the CSRF
	// guard it provides: the fixture's session cookie is `__Host-auth.session`.
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
