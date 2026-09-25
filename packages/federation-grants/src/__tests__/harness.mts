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
 * A deployment of these routes, assembled the way the module assembles one.
 *
 * The behavioural tests run against the REAL retrieval function and the real
 * in-memory store, because what is being tested is that composing them
 * preserves what they promise — a mock of core would only prove that the route
 * calls a mock. What is faked is the world outside the provider: the upstream
 * IdP's refresh, and the clock.
 */

import type {
	AuditEvent,
	AuditSink,
	Client,
	ClientRepository,
	FederationGrantConnection,
	FederationGrantCredentialState,
	FederationGrantCredentials,
	FederationGrantRefresher,
	FederationGrantStore,
	RateLimiter,
} from "@o3co/auth-provider-core";
import {
	createMemoryFederationGrantIntentStore,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	type FederationGrantAcquisitionConnection,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	type MemoryFederationGrantIntentStore,
	type MemoryFederationGrantStore,
	resolveFederationGrantRetrievalLimits,
} from "@o3co/auth-provider-core";
import express from "express";
import { vi } from "vitest";
import { createFederationGrantBackground, type FederationGrantBackground } from "#/background.mjs";
import { createFederationGrantRouter } from "#/routes.mjs";
import { FEDERATION_GRANTS_MOUNT_PATH } from "#/types.mjs";
import { createLogSpy, type LoggedLine } from "./logSpy.mjs";

export const MIN = 60_000;
export const HOUR = 3_600_000;
export const DAY = 86_400_000;

/** Grepped for in every response, audit event and captured log line (D18). */
export const SECRET = "SENTINEL-refresh-token";

export const SUBJECT = "local-subject";
export const CLIENT_ID = "worker";
export const CLIENT_SECRET = "worker-secret-value";
export const GRANT_ID = "g-1";

export const SCOPES: readonly string[] = ["openid", "offline_access", "calendar.read"];

export const connection: FederationGrantConnection = {
	name: "calendar",
	federation: "upstream",
	upstreamIssuer: "https://issuer.example",
	upstreamClientId: "provider-client",
	scopes: [...SCOPES],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
	callbackUri: "https://auth.test/session/federation-grants/callback/calendar",
};

/** Where the client's browser is sent back to at the end of a connect flow. */
export const REDIRECT_URI = "https://client.test/connected";

const confidentialClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [],
	allowedFederationGrantConnections: [connection.name],
	federationGrantRedirectUris: [REDIRECT_URI],
};

export interface Harness {
	readonly app: express.Express;
	readonly store: MemoryFederationGrantStore;
	/** Slice 6: where an intent is lodged. */
	readonly intents: MemoryFederationGrantIntentStore;
	readonly background: FederationGrantBackground;
	readonly refresh: ReturnType<typeof vi.fn<FederationGrantRefresher["refreshDelegatedToken"]>>;
	readonly events: AuditEvent[];
	readonly logs: unknown[][];
	/** Every line, with its level (`logSpy.mts`). */
	readonly lines: LoggedLine[];
	/** Mutable: what the world outside the provider answers. */
	readonly world: {
		connections: Map<string, FederationGrantConnection>;
		boundary: Date | null | Error;
		allowedConnections: readonly string[] | undefined;
		/** Read live, so a test can lower the maximum between two requests (D3). */
		maxExpiresInMs: number;
		/**
		 * What `inspect` reports about the credential. The memory store keeps
		 * credentials unsealed, so `unreadable` and `key_unavailable` are states
		 * it can never produce — and they are exactly the ones worth testing.
		 */
		credentials: FederationGrantCredentialState;
		client: Client;
		/** What the client repository throws, when it is down. */
		clientRepositoryDown: Error | undefined;
		now: Date;
		/** Slice 6: the lifetimes lodging offers. */
		lifetimes: { defaultLifetimeMs: number; maxLifetimeMs: number };
	};
	seed(over?: {
		credentials?: FederationGrantCredentials;
		expiresAt?: Date;
		id?: string;
		subject?: string;
		clientId?: string;
	}): Promise<void>;
}

export interface HarnessOptions {
	readonly withSink?: boolean;
	/** Replaces the sink that records into `events`. */
	readonly sink?: AuditSink;
	readonly rateLimiter?: RateLimiter;
	readonly background?: FederationGrantBackground;
}

export function harness(options: HarnessOptions = {}): Harness {
	const store = createMemoryFederationGrantStore();
	const intents = createMemoryFederationGrantIntentStore();
	const refresh = vi.fn<FederationGrantRefresher["refreshDelegatedToken"]>();
	const events: AuditEvent[] = [];
	const background = options.background ?? createFederationGrantBackground();

	const world: Harness["world"] = {
		connections: new Map([[connection.name, connection]]),
		boundary: null,
		allowedConnections: [connection.name],
		client: confidentialClient as unknown as Client,
		clientRepositoryDown: undefined,
		// Three days ahead of the system clock, the convention core's own
		// retrieval harness set. Two reasons: a retrieval that read `new Date()`
		// where it was handed `now()` would pass every test with the two in
		// step, and the memory store reclaims records on its OWN clock — a
		// fixture dated at a fixed instant in the past is swept before the test
		// can use it, which is how this line was found.
		now: new Date(Date.now() + 3 * DAY),
		maxExpiresInMs: 30 * DAY,
		credentials: "ok",
		lifetimes: { defaultLifetimeMs: 30 * DAY, maxLifetimeMs: 30 * DAY },
	};

	const clientRepository: ClientRepository = {
		findById: async (id) => {
			if (world.clientRepositoryDown !== undefined) throw world.clientRepositoryDown;
			return id === CLIENT_ID ? ({ ...world.client } as unknown as never) : null;
		},
		authenticate: async (id, secret) => {
			if (world.clientRepositoryDown !== undefined) throw world.clientRepositoryDown;
			if (id !== CLIENT_ID || secret !== CLIENT_SECRET) return null;
			// The allowlist is applied over the record only while the fixture
			// has one to apply: a record that simply lacks the field is what a
			// client registered before offline delegation existed looks like,
			// and overwriting it here would hide exactly that case.
			const record = { ...world.client } as Record<string, unknown>;
			if (world.allowedConnections !== undefined) {
				record.allowedFederationGrantConnections = world.allowedConnections;
			}
			return record as unknown as never;
		},
	};

	const { logger, lines } = createLogSpy();

	const sink: AuditSink | undefined =
		options.withSink === false
			? undefined
			: (options.sink ?? {
					kind: "test",
					record: async (event) => {
						events.push(event);
					},
				});

	// `inspect` goes through the world, so a test can say what the credential
	// state is without a store that can seal anything.
	// A proxy rather than a spread: a spread copies the method references once,
	// so a test that spies on the store afterwards would be spying on an object
	// the router no longer calls.
	const inspecting = new Proxy(store, {
		get(target, property, receiver) {
			if (property === "inspect") {
				return async (grantId: string, at: Date) => {
					const real = await target.inspect(grantId, at);
					return real === null ? null : { ...real, credentials: world.credentials };
				};
			}
			const value = Reflect.get(target, property, receiver);
			return typeof value === "function" ? value.bind(target) : value;
		},
	}) as FederationGrantStore;

	const limits = resolveFederationGrantRetrievalLimits({ federationGrants: {} });

	const app = express();
	app.use(
		FEDERATION_GRANTS_MOUNT_PATH,
		createFederationGrantRouter({
			store: inspecting,
			connections: world.connections,
			refresher: () => ({ refreshDelegatedToken: refresh }),
			grantsBoundary: async () => {
				if (world.boundary instanceof Error) throw world.boundary;
				return world.boundary;
			},
			limits: {
				...limits,
				get maxExpiresInMs() {
					return world.maxExpiresInMs;
				},
			},
			background,
			now: () => world.now,
			clientRepository,
			issuer: "https://auth.test",
			...(sink === undefined ? {} : { auditSink: sink }),
			rateLimiter:
				options.rateLimiter ??
				createMemoryRateLimiter({ limits: {}, defaultLimit: { limit: 1000, windowSeconds: 60 } }),
			failMode: "closed",
			logger,
			acquisition: {
				intentStore: intents,
				// Read through the world, so a test can remove a connection or
				// change the lifetimes between two requests.
				connections: {
					get: (name: string) => {
						const found = world.connections.get(name);
						return found === undefined
							? undefined
							: (found as FederationGrantAcquisitionConnection);
					},
				} as ReadonlyMap<string, FederationGrantAcquisitionConnection>,
				get limits() {
					return world.lifetimes;
				},
			},
		}),
	);

	return {
		app,
		store,
		intents,
		background,
		refresh,
		events,
		// Every line's arguments, for a test that greps them all.
		get logs() {
			return lines.map((line) => [...line.args]);
		},
		lines,
		world,
		async seed(over = {}) {
			const id = over.id ?? GRANT_ID;
			const at = world.now;
			const configured = world.connections.get(connection.name) ?? connection;
			await store.createPending({
				id,
				subject: over.subject ?? SUBJECT,
				clientId: over.clientId ?? CLIENT_ID,
				connection: connection.name,
				intent: { handle: `h-${id}`, expiresAt: new Date(at.getTime() + 10 * MIN) },
				now: at,
			});
			const written = await store.activate({
				grantId: id,
				intentHandle: `h-${id}`,
				authorization: {
					identityRevision: federationGrantIdentityRevision(configured),
					authorizationRevision: federationGrantAuthorizationRevision(configured),
					upstream: { issuer: connection.upstreamIssuer, subject: "upstream-subject" },
					scopes: [...SCOPES],
					consent: { at, sid: "sid-1", scopes: [...SCOPES] },
					authorizedAt: at,
					expiresAt: over.expiresAt ?? new Date(at.getTime() + 30 * DAY),
					resource: undefined,
				},
				credentials: over.credentials ?? {
					refreshToken: SECRET,
					accessToken: {
						value: "upstream-access-token",
						tokenType: "Bearer",
						obtainedAt: at,
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
				now: at,
			});
			if (!written.ok) throw new Error("fixture: the grant was not activated");
		},
	};
}

/** The `Authorization` header a `client_secret_basic` client sends. */
export const basic = (id = CLIENT_ID, secret = CLIENT_SECRET): string =>
	`Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

/** A client registered before offline delegation existed: the field is simply not there. */
export const clientWithoutAllowlist = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [],
} as unknown as Client;

/** A limiter that refuses everything, for proving WHERE the throttle sits. */
export const refusingLimiter: RateLimiter = {
	kind: "refusing",
	check: async () => ({ allowed: false, reason: "limit:federation_grants" }),
};

/**
 * A limiter whose backend is down, carrying a secret in its message — which is
 * what a driver does when a connection string fails to parse.
 */
export const brokenLimiter: RateLimiter = {
	kind: "broken",
	check: async () => {
		throw new Error(`redis://user:${SECRET}@limiter:6379 refused the connection`);
	},
};
