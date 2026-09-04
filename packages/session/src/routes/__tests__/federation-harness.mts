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
import { deriveFederationTransactionCookieName } from "#/federations/transaction.mjs";
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

/**
 * The transaction cookie these harness apps issue. Named from a session cookie
 * name the harness picks, and passed to the router explicitly, so a test never
 * has to guess at the router's own fallback.
 */
export const HARNESS_SESSION_COOKIE_NAME = "harness.session";
export const HARNESS_TRANSACTION_COOKIE_NAME = deriveFederationTransactionCookieName(
	HARNESS_SESSION_COOKIE_NAME,
);

/**
 * Records held by the shim's express-session `Store`, keyed exactly as the
 * route keys them. The federation transaction records land here (#494).
 */
export type HarnessRecordStore = Map<string, unknown>;

/**
 * The `req.sessionStore` an express-session deployment exposes, reduced to the
 * three methods the federation transaction store calls.
 *
 * Backed by its own map rather than by {@link HarnessSessionStore}, whose
 * entries have a session-specific shape. The real thing is one store holding
 * both, and that is what `Federation.applicationCookie.test.mts` exercises
 * against the actual `MemoryStore`.
 */
export function makeRecordStore(records: HarnessRecordStore) {
	return {
		get(sid: string, cb: (err: unknown, record?: unknown) => void) {
			cb(null, records.get(sid));
		},
		set(sid: string, record: unknown, cb?: (err?: unknown) => void) {
			// Round-tripped through JSON the way every real store does, so a
			// route cannot accidentally depend on holding the same object.
			records.set(sid, JSON.parse(JSON.stringify(record)) as unknown);
			cb?.();
		},
		destroy(sid: string, cb?: (err?: unknown) => void) {
			records.delete(sid);
			cb?.();
		},
	};
}

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
		// Shared by reference with the store entry, so anything a route wrote
		// there would survive to the response — which is how this harness can
		// still show that nothing writes there any more.
		cookie: entry.cookie,
		save(cb?: (err: unknown) => void) {
			const current = (req as unknown as { session: Record<string, unknown> }).session;
			const { save: _s, regenerate: _r, destroy: _d, cookie: _c, ...rest } = current;
			store.set(key, { data: rest, cookie: current.cookie as SessionCookieAttributes });
			cb?.(null);
			return this as unknown as import("express-session").Session;
		},
		regenerate(cb?: (err: unknown) => void) {
			// Session-ID rotation, as express-session actually performs it:
			// `Store.prototype.regenerate` destroys the record and calls
			// `store.generate`, which builds a brand-new session AND a brand-new
			// `new Cookie(cookieOptions)` from the DEPLOYMENT's configuration.
			//
			// The data goes and so do the cookie attributes. This harness used to
			// model the opposite — attributes carried across the regenerate — and
			// that mismodelling is a direct reason #494 went unnoticed: it made a
			// relaxed cookie look like something one success path tidied up, when
			// in reality regenerate is the only thing that ever reset it and it
			// runs on the success path alone.
			store.set(key, { data: {}, cookie: defaultCookie() });
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
export function makeSessionApp(
	store: HarnessSessionStore,
	records: HarnessRecordStore = new Map(),
): express.Express {
	const app = express();
	const sessionStore = makeRecordStore(records);
	app.use((req, res, next) => {
		const cookieHeader = req.headers.cookie ?? "";
		const match = cookieHeader.match(/(?:^|;\s*)sid=([^;]+)/);
		const id = match ? decodeURIComponent(match[1]) : `sid-${Math.random().toString(36).slice(2)}`;

		const session = makeSessionObject(store, id, req);
		(req as unknown as { session: Record<string, unknown> }).session = session;
		// What express-session puts on every request it handles.
		(req as unknown as { sessionStore: unknown }).sessionStore = sessionStore;

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
	/** Federation transaction records, as the route wrote them (#494). */
	records: HarnessRecordStore;
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
	const records: HarnessRecordStore = new Map();
	const app = makeSessionApp(store, records);
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
			federationTransactionCookieName: HARNESS_TRANSACTION_COOKIE_NAME,
		}),
	);

	return { app, store, records, userSessionStore, federationTokenStore, sessionFederationIndex };
}
