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
	type SessionLifecycle,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestCsrfGuard,
	createTestCsrfTokenSigner,
	createTestSessionCookiePolicy,
	makeValidAppConfig,
} from "@o3co/auth-provider-core/testing";
import { loginCompletionContract } from "@o3co/auth-provider-test-kit";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createLoginCompletion } from "#/login-completion.mjs";
import { sessionModule } from "#/module.mjs";
import { loginCompletionModule } from "#/modules/loginCompletionModule.mjs";
import { withSessionCaptures } from "./_helpers/sections.mjs";
import { fakeSessionLifecycle, sessionLifecycleTestModule } from "./_helpers/sessionLifecycle.mjs";

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
					sessionLifecycle: fakeSessionLifecycle(),
					sessionTtlMs: 3_600_000,
					csrf: guard,
				});
			},
			withSessionStoreOutage: () => {
				counted = countingStore();
				return createLoginCompletion({
					userSessionStore: downStore(),
					sessionLifecycle: fakeSessionLifecycle(),
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
				createLoginCompletion({
					userSessionStore: counted.store,
					sessionLifecycle: fakeSessionLifecycle(),
					sessionTtlMs: 1,
					csrf: guard,
				}),
			),
		).toBe(true);
	});

	it("refuses a userSessionStore without a sessionLifecycle, naming both", () => {
		expect(() =>
			createLoginCompletion({ userSessionStore: counted.store, sessionTtlMs: 1, csrf: guard }),
		).toThrow(/userSessionStore is wired, but sessionLifecycle is not/);
	});

	it("builds sessionless, with neither: the express session alone is signed in", () => {
		expect(createLoginCompletion({ sessionTtlMs: 1, csrf: guard })).toBeDefined();
	});
});

describe("the login-completion module's provider, with core's session lifecycle", () => {
	const guard = createTestCsrfGuard();
	/** Every record is created only once its lifecycle is open, or the login fails. */
	const opened = new Set<string>();
	let counted = countingStore();
	const lifecycle: SessionLifecycle = fakeSessionLifecycle({
		open: async (sid) => {
			opened.add(sid);
			return { outcome: "opened" };
		},
	});
	const openFirst = (inner: UserSessionStore): UserSessionStore => ({
		...inner,
		create: async (input) => {
			if (!opened.has(input.sid)) throw new Error(`no lifecycle record is open for ${input.sid}`);
			await inner.create(input);
		},
	});
	it.each(
		loginCompletionContract({
			build: () => {
				counted = countingStore();
				return loginCompletionModule.provides?.loginCompletion?.({
					userSessionStore: openFirst(counted.store),
					sessionLifecycle: lifecycle,
					sessionCookiePolicy: createTestSessionCookiePolicy(),
					csrfGuard: guard,
				} as never) as LoginCompletion;
			},
			records: () => counted.records(),
			csrfCookieName: guard.cookieName,
		}),
	)("$name, opening each session's lifecycle record before its record", async ({ run }) => {
		await run();
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
		async removeBySid() {},
		async delete() {},
	} as unknown as FederationTokenStore),
	// Where the session store's module is loaded, it provides these.
	providing("test:csrf-token-signer", "csrfTokenSigner", createTestCsrfTokenSigner()),
	providing("test:session-cookie-policy", "sessionCookiePolicy", createTestSessionCookiePolicy()),
	sessionLifecycleTestModule(),
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
		config: withSessionCaptures(makeValidAppConfig()) as AppConfig,
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

	it("requires the csrfGuard slot, the session cookie's policy and the session stores, and provides loginCompletion alone", () => {
		expect(loginCompletionModule.name).toBe("login-completion");
		expect(loginCompletionModule.requires).toEqual(
			expect.arrayContaining(["sessionCookiePolicy", "userSessionStore", "csrfGuard"]),
		);
		expect(loginCompletionModule.requires).not.toContain("config");
		expect(Object.keys(loginCompletionModule.provides ?? {})).toEqual(["loginCompletion"]);
	});

	it("refuses to boot with userSessionStore wired and no sessionLifecycle, naming both slots", async () => {
		const refusal = await createTestApp({
			modules: [
				loginCompletionModule,
				providing("test:user-session-store", "userSessionStore", moduleStore.store),
				providing(
					"test:session-cookie-policy",
					"sessionCookiePolicy",
					createTestSessionCookiePolicy(),
				),
				providing("test:csrf-guard", "csrfGuard", createTestCsrfGuard()),
				consumer({}),
			],
			bootstrapComponents: {
				config: withSessionCaptures(makeValidAppConfig()) as AppConfig,
				pathResolver: (s: string) => s,
			},
		}).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(caught: unknown) => caught as { reason?: unknown; cause?: { message?: unknown } },
		);
		expect(refusal, "boot must be refused").toMatchObject({
			name: "BootError",
			reason: "provides-factory-failed",
		});
		const message = String(refusal?.cause?.message);
		expect(message).toMatch(/userSessionStore is wired, but sessionLifecycle is not/);
		expect(message).toMatch(/sessionLifecycleModule/);
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
