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
 * What `enabled = true` costs a composition (#593, §5).
 *
 * Every one of these is a boot refusal rather than a per-request failure, and
 * the reason is the same each time: a grant is a user's standing consent, made
 * once and spent for weeks by a worker nobody is watching. A deployment that
 * finds out from the first request has already told a user it was set up.
 */

import type { BootstrapMap, ClientRepository, FederationProvider } from "@o3co/auth-provider-core";
import {
	BootError,
	createApp,
	createInMemorySubjectRevocation,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	defineModule,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig, makeValidFullSections } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { federationGrantsModules } from "#/index.mjs";

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

/**
 * What core's federation guard asks for the moment `federations.<name>.enabled`
 * is true. A consequence worth knowing: a deployment cannot use federation
 * grants without the session-federation wiring, because a connection has to
 * name an enabled federation.
 */
const SESSION_FEDERATION_STORES = {
	userSessionStore: {},
	sessionRPRegistry: {},
	sessionFamilyIndex: {},
	sessionFederationIndex: {},
	federationTokenStore: {},
	refreshTokenFamilyRevocation: {},
};

const storeModule = defineModule({
	name: "test-federation-grant-store",
	provides: { federationGrantStore: () => createMemoryFederationGrantStore() },
});

/**
 * A store that says it keeps grants somewhere they survive a restart. The port
 * exposes `kind` and nothing else about persistence, so that is what the
 * durability pairing is judged on.
 */
const durableStoreModule = defineModule({
	name: "test-durable-federation-grant-store",
	provides: {
		federationGrantStore: () => ({ ...createMemoryFederationGrantStore(), kind: "redis" }),
	} as never,
});

/** The single-boundary surface #296 shipped, with no grants boundary on it. */
const olderRevocation = {
	kind: "redis",
	revokeBefore: async () => undefined,
	revokedBefore: async () => null,
};

/** An adapter with BOTH delegated methods: the capability slice 2 defined. */
const delegated = {
	buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
	refreshDelegatedToken: async () => ({}),
} as unknown as FederationProvider;

/** An adapter with an ordinary session refresh and nothing else. */
const sessionOnly = { refreshToken: async () => ({}) } as unknown as FederationProvider;

const federationModule = (name: string, provider: FederationProvider) =>
	defineModule({
		name: `test-federation-${name}`,
		contributes: {
			federations: { [name]: () => provider },
			// A federation must be contributed with its redirect policy, which
			// is a boot invariant of its own and nothing to do with grants.
			federationRedirectPolicies: {
				[name]: () => ({
					validateRedirect: () => ({ ok: true as const, value: undefined }),
					resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
				}),
			},
		} as never,
	});

const CONNECTION = {
	federation: "upstream",
	scopes: ["openid", "offline_access"],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
};

interface Setup {
	readonly enabled?: unknown;
	readonly connections?: Record<string, unknown>;
	readonly grants?: Record<string, unknown>;
	readonly withStore?: boolean;
	/** `"memory"` is the bundled pair; `"durable"` says grants outlive the process. */
	readonly store?: "memory" | "durable";
	/** What ends a grant a user withdrew on a replica that never saw the withdrawal. */
	readonly revocation?: "memory" | "older" | "absent";
	readonly withLimiter?: boolean;
	readonly withAudit?: boolean;
	readonly failMode?: unknown;
	readonly provider?: FederationProvider | null;
	/** The federation module listed BEFORE the routes, or after. */
	readonly federationFirst?: boolean;
}

const boot = (setup: Setup) => {
	const full = makeValidFullSections();
	const federation =
		setup.provider === null ? [] : [federationModule("upstream", setup.provider ?? delegated)];
	const modules = [
		...(setup.federationFirst === false ? [] : federation),
		...federationGrantsModules,
		...(setup.withStore === false
			? []
			: [setup.store === "durable" ? durableStoreModule : storeModule]),
		...(setup.federationFirst === false ? federation : []),
	];
	return createApp({
		modules,
		bootstrapComponents: {
			config: {
				...makeValidCoreConfig(),
				federations: {
					upstream: { enabled: true, issuer: "https://issuer.example", clientId: "cid" },
				},
				rateLimit: { ...full.rateLimit, failMode: setup.failMode ?? "closed" },
				...(setup.withAudit === false ? {} : { audit: { sink: { type: "none" } } }),
				federationGrants: {
					enabled: setup.enabled ?? true,
					connections: setup.connections ?? { calendar: CONNECTION },
					...(setup.grants ?? {}),
				},
			},
			pathResolver: (s: string) => s,
			clientRepository,
			// Enabling a federation at all brings the session-federation stores
			// with it — a federation is first of all a way to log in, and that
			// guard is not this feature's. Present but empty: what is under test
			// here is the grant refusals, and nothing in this file logs anyone in.
			...SESSION_FEDERATION_STORES,
			// The boundary a grant is compared against on every disclosure
			// (D13). Bundled here because every composition that enables the
			// feature needs one, which is the point of the refusals below.
			...(setup.revocation === "absent"
				? {}
				: {
						subjectRevocation:
							setup.revocation === "older" ? olderRevocation : createInMemorySubjectRevocation(),
					}),
			...(setup.withLimiter === false
				? {}
				: {
						rateLimiter: createMemoryRateLimiter({
							limits: {},
							defaultLimit: { limit: 60, windowSeconds: 60 },
						}),
					}),
		} as unknown as BootstrapMap,
	});
};

describe("enabling the feature", () => {
	it("boots a composition that has everything it needs", async () => {
		const handle = await boot({});
		expect(handle.components.federationGrantStore).toBeDefined();
		await handle.dispose();
	});

	it("boots whether the federation is contributed before the routes or after", async () => {
		// The delegated capability is resolved in the route contribution phase,
		// after named federations are assembled. Checking it while components
		// are materialised would refuse a valid composition for the order its
		// author happened to write.
		const handle = await boot({ federationFirst: false });
		await handle.dispose();
	});

	it("refuses to boot with nowhere to keep grants", async () => {
		await expect(boot({ withStore: false })).rejects.toThrow(/federationGrantStore/);
	});

	it("refuses to boot with nothing that can end a grant", async () => {
		// The backstop, not a nicety: a grant outlives the session it was
		// agreed through, so the boundary is what reaches one on a replica that
		// never saw the withdrawal. Slice 4 answered 503 per request; a
		// composition error belongs here.
		await expect(boot({ revocation: "absent" })).rejects.toThrow(/subjectRevocation component/);
	});

	it("refuses an adapter that carries only the boundary #296 shipped", async () => {
		await expect(boot({ revocation: "older" })).rejects.toThrow(/grantsRevokedBefore/);
	});

	it("refuses grants that outlive the process beside a boundary that does not", async () => {
		// A restart — or simply the replica that never held it — would disclose
		// a credential for a grant that was revoked.
		await expect(boot({ store: "durable" })).rejects.toThrow(/outlive the process/);
	});

	it("refuses to boot with no throttle in front of an opaque grant id", async () => {
		await expect(boot({ withLimiter: false })).rejects.toThrow(/rateLimiter/);
	});

	it("refuses to boot without the product's limiter-outage policy", async () => {
		await expect(boot({ failMode: "maybe" })).rejects.toThrow(/failMode/);
	});

	it("refuses a retrieval limit the promises cannot be kept under", async () => {
		// A lock that cannot outlive a refresh and its persistence lets two
		// replicas present the same refresh token (D12).
		await expect(boot({ grants: { refreshLockTtlMs: 1_000 } })).rejects.toThrow();
		await expect(boot({ grants: { maxExpiresIn: 31_536_001 } })).rejects.toThrow(/maxExpiresIn/);
	});

	it("refuses a connection whose shape core's own schema can already see is wrong", async () => {
		// The block is declared in `fullSectionsSchema`, so the parse catches a
		// missing boundary before any module reads it. That is the earliest
		// this can be caught and it is where it should be caught.
		const error = await boot({ connections: { calendar: { ...CONNECTION, boundary: "" } } }).then(
			() => undefined,
			(thrown: unknown) => thrown,
		);
		const { issues } = (error as BootError).details as {
			issues: readonly { readonly path: readonly PropertyKey[] }[];
		};
		expect(issues.some((i) => i.path.join(".").endsWith("boundary"))).toBe(true);
	});

	it("refuses a connection whose meaning is wrong, which a schema cannot see", async () => {
		// Shape and meaning are different questions. `openid` missing is a
		// well-formed list of scope tokens; what it is not is a connection that
		// can pin a grant to an upstream account, because without an id_token
		// there is no subject to pin it to.
		await expect(
			boot({ connections: { calendar: { ...CONNECTION, scopes: ["offline_access"] } } }),
		).rejects.toThrow(/openid/);
		// Taking over a parameter the provider computes is not customisation.
		await expect(
			boot({
				connections: {
					calendar: { ...CONNECTION, authorizationParams: { code_challenge: "x" } },
				},
			}),
		).rejects.toThrow(/code_challenge/);
	});

	it("refuses a connection pointing at a federation nothing contributes", async () => {
		await expect(boot({ provider: null })).rejects.toThrow(/upstream/);
	});

	it("refuses a federation whose adapter cannot act without the user", async () => {
		// An ordinary `refreshToken` renews a token inside a session with the
		// session's own credentials. It says nothing about whether this
		// provider may act for a user who is not present, which is the entire
		// question offline delegation asks.
		await expect(boot({ provider: sessionOnly })).rejects.toThrow(/delegated/);
	});

	it("refuses to discard every disclosure without being told to", async () => {
		await expect(boot({ withAudit: false })).rejects.toThrow(/auditSink|audit\.sink\.type/);
	});

	it("boots with an empty connection map, because removing the last one is operable", async () => {
		const handle = await boot({ connections: {}, provider: null });
		await handle.dispose();
	});
});

describe("leaving the feature off", () => {
	it('reads the spellings an environment variable arrives in, so "true" enables', async () => {
		// #288: HOCON substitutes `${?FEDERATION_GRANTS_ENABLED}` as a string,
		// always. A bare `z.boolean()` would leave an operator who exported the
		// documented variable with the feature silently off — the one failure
		// mode a secure default must not have, because it looks like a working
		// deployment.
		await expect(boot({ enabled: "true", withStore: false })).rejects.toThrow(
			/federationGrantStore/,
		);
		await expect(boot({ enabled: "1", withStore: false })).rejects.toThrow(/federationGrantStore/);
	});

	it('reads "false", "0" and an exported-but-empty variable as off', async () => {
		for (const off of ["false", "0", ""]) {
			const handle = await boot({
				enabled: off,
				withStore: false,
				withLimiter: false,
				withAudit: false,
				provider: null,
			});
			expect(handle.components.federationGrantStore).toBeUndefined();
			await handle.dispose();
		}
	});

	it("refuses a value that is neither, naming the spellings it accepts", async () => {
		// `z.coerce.boolean()` would have read "yes" as true and "no" as true
		// as well, so an operator switching the feature off would have switched
		// it on.
		const error = await boot({ enabled: "yes" }).then(
			() => undefined,
			(thrown: unknown) => thrown,
		);
		expect(error).toBeInstanceOf(BootError);
		const { issues } = (error as BootError).details as {
			issues: readonly { readonly path: readonly PropertyKey[]; readonly message: string }[];
		};
		const issue = issues.find((i) => i.path.join(".") === "federationGrants.enabled");
		expect(issue?.message).toMatch(/"true", "false", "1" or "0"/);
	});
});
