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
 * Test harness for the federation routes, modelling what the shim in
 * `Federation.test.mts` does not: a real per-session `cookie` attribute bag,
 * carried through to a `Set-Cookie` header the way express-session does.
 * Whether the session cookie reaches a `form_post` federation's cross-site
 * POST callback is a question about cookie attributes, which a shim that
 * hard-codes `res.cookie("sid", id, { httpOnly: true })` cannot answer.
 */

import type {
	AuditSink,
	FederationProvider,
	FederationTokenStore,
	Logger,
	SessionLifecycle,
	SessionLifecycleStore,
	SessionRequirementResolver,
	SubjectRevocation,
	SubjectSessionIndex,
	UserRepository,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { createTestFederationSettings, resolverForTests } from "@o3co/auth-provider-core/testing";
import express from "express";
import { vi } from "vitest";
import { fakeSessionLifecycle } from "#/__tests__/_helpers/sessionLifecycle.mjs";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { deriveFederationTransactionCookieName } from "#/federations/transaction.mjs";
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
 * The transaction cookie these harness apps issue, named from a session
 * cookie name the harness picks, as the session module names it from the
 * deployment's: the router is handed its name and has none of its own.
 */
export const HARNESS_SESSION_COOKIE_NAME = "harness.session";
export const HARNESS_TRANSACTION_COOKIE_NAME = deriveFederationTransactionCookieName(
	HARNESS_SESSION_COOKIE_NAME,
);

/**
 * The issuer a harness test registers its requirements' pages on, as boot
 * registers them on `oauth.jwt.issuer`. The router is handed no issuer: the
 * page arrives resolved.
 */
export const HARNESS_ISSUER = "https://as.example.com";

/**
 * Records held by the shim's express-session `Store`, keyed exactly as the
 * route keys them. The federation transaction records land here.
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
		// The attribute bag express-session exposes as `req.session.cookie`,
		// shared by reference with the store entry, so anything a route wrote
		// there would survive to the response, where a test can see it.
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
			// The data goes and so do the cookie attributes.
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
			const current = (req as unknown as { session?: Record<string, unknown> }).session;
			// A route that dropped the cookie session names none.
			if (!res.headersSent && current !== undefined) {
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

export function makeFederationTokenStore(): FederationTokenStore & {
	attach: ReturnType<typeof vi.fn>;
	delete: ReturnType<typeof vi.fn>;
} {
	return {
		kind: "memory",
		attach: vi.fn(async () => {}),
		get: vi.fn(async () => null),
		getVersioned: vi.fn(async () => null),
		replaceIf: vi.fn(async () => ({ outcome: "missing" as const })),
		removeIf: vi.fn(async () => ({ outcome: "missing" as const })),
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
	/** Federation transaction records, as the route wrote them. */
	records: HarnessRecordStore;
	userSessionStore: ReturnType<typeof makeUserSessionStore>;
	federationTokenStore: ReturnType<typeof makeFederationTokenStore>;
	/** The session lifecycle the router was handed: a fake whose members are spies, by default. */
	sessionLifecycle: SessionLifecycle;
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
	requirements,
	subjectRevocation,
	sessionLifecycleStore,
	sessionLifecycle,
	auditSink,
	logger,
}: {
	providers: ReadonlyMap<string, FederationProvider>;
	providerCallbackUrls: ReadonlyMap<string, string>;
	userRepository?: UserRepository;
	subjectSessionIndex?: SubjectSessionIndex;
	/** The session requirements the link routes admit through; none by default. */
	requirements?: SessionRequirementResolver;
	subjectRevocation?: SubjectRevocation;
	sessionLifecycleStore?: SessionLifecycleStore;
	sessionLifecycle?: SessionLifecycle;
	auditSink?: AuditSink;
	logger?: Logger;
}): HarnessApp {
	const store: HarnessSessionStore = new Map();
	const records: HarnessRecordStore = new Map();
	const app = makeSessionApp(store, records);
	const userSessionStore = makeUserSessionStore();
	const federationTokenStore = makeFederationTokenStore();
	const lifecycle = sessionLifecycle ?? fakeSessionLifecycle();

	app.use(
		createRouter(express, {
			federationSettings: createTestFederationSettings(),
			federationProviders: providers,
			federationRedirectPolicyResolver: new Map(
				[...providers.keys()].map((name) => [name, makePermissivePolicy()]),
			) as never,
			providerCallbackUrls,
			userRepository: userRepository ?? makeUserRepository(),
			userSessionStore,
			...(subjectSessionIndex ? { subjectSessionIndex } : {}),
			...(subjectRevocation ? { subjectRevocation } : {}),
			...(sessionLifecycleStore ? { sessionLifecycleStore } : {}),
			sessionLifecycle: lifecycle,
			federationTokenStore,
			federationTransactionCookieName: HARNESS_TRANSACTION_COOKIE_NAME,
			requirements: requirements ?? resolverForTests([], { actions: SESSION_ADMISSION_ACTIONS }),
			...(auditSink ? { auditSink } : {}),
			...(logger ? { logger } : {}),
		}),
	);

	return {
		app,
		store,
		records,
		userSessionStore,
		federationTokenStore,
		sessionLifecycle: lifecycle,
	};
}
