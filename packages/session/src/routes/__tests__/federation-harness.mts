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
 * Test harness for the federation routes, with the one thing
 * `Federation.test.mts`'s older shim does not model: a real per-session
 * `cookie` attribute bag, emitted as a `Set-Cookie` header on the way out.
 *
 * `form_post` federations turn on a cross-site POST callback, and the whole
 * question that raises — does the session cookie actually reach the callback? —
 * is a question about cookie attributes. A shim that hard-codes
 * `res.cookie("sid", id, { httpOnly: true })` cannot answer it, so this one
 * carries the session's own `cookie` object through to the response the way
 * express-session does.
 */

import type {
	FederationTokenStore,
	SessionFederationIndex,
	SubjectSessionIndex,
	UserRepository,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import express from "express";
import { vi } from "vitest";
import type { FederationProvider } from "#/federations/types.mjs";
import { createRouter } from "#/routes/Federation.mjs";

export type SessionCookieAttributes = {
	sameSite: "lax" | "strict" | "none";
	secure: boolean;
	httpOnly: boolean;
};

type StoredSession = {
	data: Record<string, unknown>;
	cookie: SessionCookieAttributes;
};

export type HarnessSessionStore = Map<string, StoredSession>;

/** The deployment default this repo's config schema encourages: Lax, non-Secure locally. */
const defaultCookie = (): SessionCookieAttributes => ({
	sameSite: "lax",
	secure: false,
	httpOnly: true,
});

function makeSessionObject(
	store: HarnessSessionStore,
	key: string,
	req: express.Request,
): Record<string, unknown> {
	const entry = store.get(key) ?? { data: {}, cookie: defaultCookie() };
	store.set(key, entry);
	const session: Record<string, unknown> = {
		...entry.data,
		// The attribute bag express-session exposes as `req.session.cookie`, and
		// the object `applyCrossSiteStateCookie` relaxes. Shared by reference with
		// the store entry so a route's mutation survives to the response.
		cookie: entry.cookie,
		save(cb?: (err: unknown) => void) {
			const current = (req as unknown as { session: Record<string, unknown> }).session;
			const { save: _s, regenerate: _r, destroy: _d, cookie: _c, ...rest } = current;
			store.set(key, { data: rest, cookie: current.cookie as SessionCookieAttributes });
			cb?.(null);
			return this as unknown as import("express-session").Session;
		},
		regenerate(cb?: (err: unknown) => void) {
			// Session-ID rotation: the data goes, the cookie attributes stay (a
			// regenerated session is still delivered to the same browser).
			store.set(key, { data: {}, cookie: (store.get(key) ?? { cookie: defaultCookie() }).cookie });
			const fresh = makeSessionObject(store, key, req);
			(req as unknown as { session: Record<string, unknown> }).session = fresh;
			cb?.(null);
			return this as unknown as import("express-session").Session;
		},
		destroy(cb?: (err: unknown) => void) {
			store.delete(key);
			cb?.(null);
			return this as unknown as import("express-session").Session;
		},
	};
	return session;
}

/**
 * Express app whose session middleware writes the session's own cookie
 * attributes into `Set-Cookie`, deferred to `res.end` so that a route which
 * relaxed them mid-request is the one the browser hears about.
 */
export function makeSessionApp(store: HarnessSessionStore): express.Express {
	const app = express();
	app.use((req, res, next) => {
		const cookieHeader = req.headers.cookie ?? "";
		const match = cookieHeader.match(/(?:^|;\s*)sid=([^;]+)/);
		const id = match ? decodeURIComponent(match[1]) : `sid-${Math.random().toString(36).slice(2)}`;

		const session = makeSessionObject(store, id, req);
		(req as unknown as { session: Record<string, unknown> }).session = session;

		const originalEnd = res.end.bind(res);
		res.end = ((...args: Parameters<typeof originalEnd>) => {
			if (!res.headersSent) {
				const current = (req as unknown as { session: Record<string, unknown> }).session;
				const attributes = current.cookie as SessionCookieAttributes;
				res.cookie("sid", id, {
					httpOnly: attributes.httpOnly,
					secure: attributes.secure,
					sameSite: attributes.sameSite,
				});
			}
			return originalEnd(...args);
		}) as typeof res.end;

		next();
	});
	return app;
}

export function makeUserRepository(
	user: { id: string; username: string; [k: string]: unknown } | null = {
		id: "user-1",
		username: "alice",
	},
): UserRepository {
	return {
		authenticate: vi.fn(async () => user),
		authenticateByToken: vi.fn(async () => user),
	};
}

export function makeUserSessionStore(): UserSessionStore & {
	create: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		create: vi.fn(async () => {}),
		get: vi.fn(async () => null),
		delete: vi.fn(async () => {}),
	};
}

export function makeSessionFederationIndex(): SessionFederationIndex {
	return {
		kind: "memory",
		addFederation: vi.fn(async () => {}),
		listFederations: vi.fn(async () => []),
		removeFederation: vi.fn(async () => {}),
		removeBySid: vi.fn(async () => {}),
	} as SessionFederationIndex;
}

export function makeFederationTokenStore(): FederationTokenStore & {
	attach: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		attach: vi.fn(async () => {}),
		get: vi.fn(async () => null),
		update: vi.fn(async () => {}),
		removeBySid: vi.fn(async () => {}),
		delete: vi.fn(async () => {}),
	};
}

export function makePermissivePolicy() {
	return {
		validateRedirect: () => ({ ok: true as const, value: undefined }),
		resolveCallbackRedirect: (s: { redirectTo?: string }) => ({
			ok: true as const,
			value: s.redirectTo ?? "/",
		}),
	};
}

export type HarnessApp = {
	app: express.Express;
	store: HarnessSessionStore;
	userSessionStore: ReturnType<typeof makeUserSessionStore>;
	federationTokenStore: ReturnType<typeof makeFederationTokenStore>;
	sessionFederationIndex: SessionFederationIndex;
};

/**
 * Mount the federation router over the cookie-carrying session shim. Tests
 * read the persisted session straight out of the returned `store`, so no
 * inspection endpoint is needed — and none exists to be mistaken for part of
 * the router's surface.
 */
export function buildFederationApp({
	providers,
	providerCallbackUrls,
	userRepository,
	subjectSessionIndex,
}: {
	providers: ReadonlyMap<string, FederationProvider>;
	providerCallbackUrls: ReadonlyMap<string, string>;
	userRepository?: UserRepository;
	subjectSessionIndex?: SubjectSessionIndex;
}): HarnessApp {
	const store: HarnessSessionStore = new Map();
	const app = makeSessionApp(store);
	const userSessionStore = makeUserSessionStore();
	const federationTokenStore = makeFederationTokenStore();
	const sessionFederationIndex = makeSessionFederationIndex();

	app.use(
		createRouter(express, {
			config: {} as never,
			federationProviders: providers,
			federationRedirectPolicyResolver: new Map(
				[...providers.keys()].map((name) => [name, makePermissivePolicy()]),
			) as never,
			providerCallbackUrls,
			userRepository: userRepository ?? makeUserRepository(),
			userSessionStore,
			sessionFederationIndex,
			...(subjectSessionIndex ? { subjectSessionIndex } : {}),
			federationTokenStore,
		}),
	);

	return { app, store, userSessionStore, federationTokenStore, sessionFederationIndex };
}
