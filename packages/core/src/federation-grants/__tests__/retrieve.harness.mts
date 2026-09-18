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

import { vi } from "vitest";
import {
	createMemoryFederationGrantStore,
	type MemoryFederationGrantStore,
} from "#/federation-grants/memory.mjs";
import type {
	FederationGrantAuditEvent,
	FederationGrantRefreshedToken,
	FederationGrantRefresher,
	RetrieveFederationGrantTokenDeps,
	RetrieveFederationGrantTokenRequest,
} from "#/federation-grants/retrieve.mjs";
import {
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
} from "#/federation-grants/revision.mjs";
import type {
	AuthorizedFederationGrant,
	FederationGrantConnection,
	FederationGrantCredentials,
} from "#/federation-grants/types.mjs";

export const MIN = 60_000;
export const HOUR = 3_600_000;
export const DAY = 86_400_000;

/** Where the INJECTED clock starts. */
export const T0 = new Date("2026-09-18T00:00:00.000Z");
export const at = (ms: number): Date => new Date(T0.getTime() + ms);

/**
 * The injected clock runs three days ahead of the system clock the fake timers
 * drive. With the two in step, a retrieval that read `new Date()` where it was
 * handed `deps.now()` would pass every test: "`now` is injected everywhere it
 * is read" (the ADR's acceptance criteria) has to be something a test can see.
 * Durations — timers, the lock's TTL — are the same on both.
 */
export const CLOCK_AHEAD_MS = 3 * DAY;
/** What `deps.now()` answers. Tests read the time through this, never through `new Date()`. */
export const now = (): Date => new Date(Date.now() + CLOCK_AHEAD_MS);
/** Moves the injected clock to `date`, and the timers with it. */
export const setNow = (date: Date): void => {
	vi.setSystemTime(new Date(date.getTime() - CLOCK_AHEAD_MS));
};

/** Grepped for in every denial and every audit event: no long-lived secret may appear in either (D18). */
export const SECRET = "SENTINEL-refresh-token";

/** What the upstream GRANTED at authorization, and what a refresh asks for again. */
export const SCOPES: readonly string[] = ["openid", "offline_access", "calendar.read"];
/**
 * What the user CONSENTED to: one scope more than the upstream granted. The two
 * differ so that a test can tell which one a rule reads — eligibility judges
 * against the consent, a refresh asks for what was granted.
 */
export const CONSENTED: readonly string[] = [...SCOPES, "calendar.write"];

export const connection: FederationGrantConnection = {
	name: "okta-calendar",
	federation: "okta",
	upstreamIssuer: "https://dev-1.okta.test",
	upstreamClientId: "0oa-calendar",
	scopes: [...CONSENTED],
	boundary: "prod-eu",
	maxAccessTokenLifetime: 3600,
};

export const limits: RetrieveFederationGrantTokenDeps["limits"] = {
	maxExpiresInMs: 90 * DAY,
	revocationSkewMs: 1_000,
	refreshBufferMs: 30_000,
	ineligibleRetryAfterMs: 300_000,
	refreshFailureBackoffMs: 30_000,
	upstreamTimeoutMs: 10_000,
	upstreamHardTimeoutMs: 25_000,
	refreshLockTtlMs: 30_000,
	lockWaitMs: 5_000,
	persistRetryBudgetMs: 3_000,
};

export const request: RetrieveFederationGrantTokenRequest = {
	grantId: "g-1",
	clientId: "agent",
	subject: "u-1",
	allowedConnections: ["okta-calendar"],
	correlationId: "req-1",
};

/** What the upstream answers a refresh with, as the adapter reports it: an hour, anchored at `obtained`. */
export const refreshed = (
	tag: string,
	obtained: Date,
	over: Partial<FederationGrantRefreshedToken> = {},
): FederationGrantRefreshedToken => ({
	accessToken: `at-${tag}`,
	refreshToken: `${SECRET}-${tag}`,
	expiresIn: 3600,
	expiresAt: new Date(obtained.getTime() + HOUR),
	tokenType: "Bearer",
	...over,
});

export interface Harness {
	readonly store: MemoryFederationGrantStore;
	/** Mutable, so that a test can change a limit or swap a dependency mid-way. */
	readonly deps: {
		-readonly [K in keyof RetrieveFederationGrantTokenDeps]: RetrieveFederationGrantTokenDeps[K];
	};
	readonly refresh: ReturnType<typeof vi.fn<FederationGrantRefresher["refreshDelegatedToken"]>>;
	readonly events: FederationGrantAuditEvent[];
	/** What `deps.background` was handed: the work that outlived a call. */
	readonly background: Promise<void>[];
	/** Mutable: what `deps.connection` and `deps.grantsBoundary` answer. */
	readonly world: {
		connections: Map<string, FederationGrantConnection>;
		boundary: Date | null | Error;
	};
	/**
	 * Lodges and activates `g-1` now for `u-1` / `agent`, under the connection as
	 * the world has it, with an access token obtained now and good for an hour,
	 * carrying every consented scope.
	 */
	seed(over?: {
		credentials?: FederationGrantCredentials;
		expiresAt?: Date;
		id?: string;
		/** When the user agreed, for a test that turns on which grants were consented when. */
		consentAt?: Date;
	}): Promise<AuthorizedFederationGrant>;
}

export function harness(): Harness {
	const store = createMemoryFederationGrantStore();
	const refresh = vi.fn<FederationGrantRefresher["refreshDelegatedToken"]>();
	const events: FederationGrantAuditEvent[] = [];
	const background: Promise<void>[] = [];
	const world: Harness["world"] = {
		connections: new Map([[connection.name, connection]]),
		boundary: null,
	};

	const deps: Harness["deps"] = {
		store,
		connection: (name) => world.connections.get(name),
		refresher: () => ({ refreshDelegatedToken: refresh }),
		grantsBoundary: async () => {
			if (world.boundary instanceof Error) throw world.boundary;
			return world.boundary;
		},
		now,
		limits,
		background: (work) => {
			background.push(work);
		},
		audit: (event) => {
			events.push(event);
		},
	};

	return {
		store,
		deps,
		refresh,
		events,
		background,
		world,
		async seed(over = {}) {
			const id = over.id ?? "g-1";
			const seededAt = now();
			// Under the connection as the world has it NOW, so that a test which
			// reconfigures it first gets a grant whose revisions match.
			const configured = world.connections.get(connection.name) ?? connection;
			await store.createPending({
				id,
				subject: "u-1",
				clientId: "agent",
				connection: connection.name,
				intent: { handle: `h-${id}`, expiresAt: new Date(seededAt.getTime() + 10 * MIN) },
				now: seededAt,
			});
			const written = await store.activate({
				grantId: id,
				intentHandle: `h-${id}`,
				authorization: {
					identityRevision: federationGrantIdentityRevision(configured),
					authorizationRevision: federationGrantAuthorizationRevision(configured),
					upstream: { issuer: connection.upstreamIssuer, subject: "00u-alice" },
					...(configured.resource !== undefined ? { resource: configured.resource } : {}),
					scopes: [...SCOPES],
					consent: { at: over.consentAt ?? seededAt, sid: "sid-1", scopes: [...CONSENTED] },
					authorizedAt: seededAt,
					expiresAt: over.expiresAt ?? new Date(seededAt.getTime() + 30 * DAY),
				},
				credentials: over.credentials ?? {
					refreshToken: SECRET,
					accessToken: {
						value: "at-0",
						tokenType: "Bearer",
						obtainedAt: seededAt,
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
				now: seededAt,
			});
			if (!written.ok || written.grant.status !== "active") {
				throw new Error("fixture: the grant was not activated");
			}
			return written.grant;
		},
	};
}
