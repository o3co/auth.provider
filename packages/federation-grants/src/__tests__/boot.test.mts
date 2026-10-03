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
 * What `enabled = true` costs a composition.
 *
 * Every one of these is a boot refusal rather than a per-request failure, and
 * the reason is the same each time: a grant is a user's standing consent, made
 * once and spent for weeks by a worker nobody is watching. A deployment that
 * finds out from the first request has already told a user it was set up.
 */

import type {
	BootstrapMap,
	ClientRepository,
	FederationProvider,
	LoginEntry,
} from "@o3co/auth-provider-core";
import {
	BootError,
	createApp,
	createInMemorySubjectRevocation,
	createMemoryFederationGrantStore,
	createMemoryRateLimiter,
	defineModule,
	InMemoryUserRepository,
} from "@o3co/auth-provider-core";
import {
	coreConfigForTests,
	createTestOAuthTokenSettings,
	federationTypeForTests,
	makeValidCoreConfig,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import {
	createFederationGrantBackground,
	type FederationGrantBackground,
	federationGrantsModules,
} from "#/index.mjs";
import {
	ACQUISITION_GRANT_SETTINGS,
	acquisitionComponents,
	callbackUrlFor,
	sessionMiddlewareModule,
} from "./acquisitionFixture.mjs";

const clientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

/**
 * What core's federation guard asks for the moment `core.federations.<name>.enabled`
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

/** The same store, whose cleanup writes to `order`. */
const storeModuleClosingInto = (order: string[]) =>
	defineModule({
		name: "test-federation-grant-store",
		provides: { federationGrantStore: () => createMemoryFederationGrantStore() },
		lifecycle: {
			federationGrantStore: {
				cleanup: () => {
					order.push("store closed");
				},
			},
		},
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

/** The memory store without `member`, as a store written against an earlier port would be. */
const storeModuleWithout = (member: "takeRotation" | "refundRotation") =>
	defineModule({
		name: `test-federation-grant-store-without-${member}`,
		provides: {
			federationGrantStore: () => {
				const { [member]: _none, ...store } = createMemoryFederationGrantStore();
				return store;
			},
		} as never,
	});

/** A single-boundary adapter: `revokeBefore` and `revokedBefore`, with no grants boundary on it. */
const olderRevocation = {
	kind: "redis",
	revokeBefore: async () => undefined,
	revokedBefore: async () => null,
};

/** An adapter with all three delegated methods: the whole capability (the federation-grants ADR, D17). */
const delegated = {
	name: "upstream",
	buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
	exchangeDelegatedCode: async () => ({
		upstream: { issuer: "https://issuer.example", subject: "upstream-1" },
		tokens: {},
	}),
	refreshDelegatedToken: async () => ({}),
} as unknown as FederationProvider;

/** Two of the three delegated methods, without the code exchange. */
const slice2Pair = {
	name: "upstream",
	buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
	refreshDelegatedToken: async () => ({}),
} as unknown as FederationProvider;

/** A custom adapter with the capability, whose callbacks arrive as a cross-site POST. */
const formPost = {
	name: "upstream",
	responseMode: "form_post",
	buildDelegatedAuthorizationUrl: () => new URL("https://issuer.example/authorize"),
	exchangeDelegatedCode: async () => ({
		upstream: { issuer: "https://issuer.example", subject: "s" },
		tokens: {},
	}),
	refreshDelegatedToken: async () => ({}),
} as unknown as FederationProvider;

/** An adapter with an ordinary session refresh and nothing else. */
const sessionOnly = {
	name: "upstream",
	refreshToken: async () => ({}),
} as unknown as FederationProvider;

/** The type of the `upstream` entry, handled by the module below. */
const UPSTREAM_TYPE = "upstream-idp";

/**
 * The module that handles the `upstream` entry's type: its provider is the
 * one a test passes, and the fixture's redirect policy, which is a boot
 * invariant of its own and nothing to do with grants, stands beside it.
 */
const federationModule = (provider: FederationProvider) =>
	federationTypeForTests(UPSTREAM_TYPE, { provider: () => provider });

const CONNECTION = {
	federation: "upstream",
	scopes: ["openid", "offline_access"],
	boundary: "production",
	maxAccessTokenLifetime: 3600,
	callbackURL: callbackUrlFor("calendar"),
};

interface Setup {
	readonly enabled?: unknown;
	readonly connections?: Record<string, unknown>;
	readonly grants?: Record<string, unknown>;
	readonly withStore?: boolean;
	/**
	 * `"memory"` is the bundled pair; `"durable"` says grants outlive the
	 * process; `"without-take"` / `"without-refund"` lack a rotation member.
	 */
	readonly store?: "memory" | "durable" | "without-take" | "without-refund";
	/** What ends a grant a user withdrew on a replica that never saw the withdrawal. */
	readonly revocation?: "memory" | "older" | "absent";
	readonly withLimiter?: boolean;
	readonly withAudit?: boolean;
	/** Also writes `audit.sink.type = "none"`, the path the audit sink's declared absence moved from. */
	readonly oldAuditDeclaration?: boolean;
	readonly provider?: FederationProvider | null;
	/** The federation module listed BEFORE the routes, or after. */
	readonly federationFirst?: boolean;
	/** Somewhere to lodge an intent. */
	readonly withIntentStore?: boolean;
	/**
	 * The repository the identity check asks (the federation-grants ADR, D7
	 * check 5). `without-lookup` has no lookup; `bundled` is
	 * `InMemoryUserRepository`, which covers no registration.
	 */
	readonly userRepository?: "with-lookup" | "without-lookup" | "bundled";
	/** The durable sessions the connect flow re-reads. */
	readonly withUserSessionStore?: boolean;
	/**
	 * Where connect sends a browser that is not signed in — the `loginEntry`
	 * slot; `"unconfigured"`, the entry the session module
	 * provides when `session.loginPage.url` names no page.
	 */
	readonly withLoginEntry?: boolean | "unconfigured";
	/**
	 * The CSRF policy the consent answer is held to — the `csrfGuard` slot;
	 * `"without-check"`, a guard with no `check` to ask.
	 */
	readonly withCsrfGuard?: boolean | "without-check";
	/** The oauthTokenSettings the composition holds; none by default. */
	readonly tokenSettingsIssuer?: string;
	/** Where the memory store's cleanup records that it ran; no cleanup by default. */
	readonly storeClosed?: string[];
	/** A registry the host supplies through `overrideComponents`, in place of the module's. */
	readonly background?: FederationGrantBackground;
}

/**
 * The login entry the session module provides when `session.loginPage.url`
 * names no page: built, and failing where the page is read.
 */
const UNCONFIGURED_LOGIN_ENTRY: LoginEntry = Object.freeze(
	Object.defineProperties({} as LoginEntry, {
		url: {
			get: () => {
				throw new Error("session.loginPage.url is not configured");
			},
			enumerable: true,
		},
		urlFor: {
			value: () => {
				throw new Error("session.loginPage.url is not configured");
			},
			enumerable: true,
		},
	}),
);

const boot = (setup: Setup) => {
	const federation = setup.provider === null ? [] : [federationModule(setup.provider ?? delegated)];
	const modules = [
		...(setup.federationFirst === false ? [] : federation),
		sessionMiddlewareModule,
		...federationGrantsModules,
		...(setup.withStore === false
			? []
			: [
					setup.store === "durable"
						? durableStoreModule
						: setup.store === "without-take"
							? storeModuleWithout("takeRotation")
							: setup.store === "without-refund"
								? storeModuleWithout("refundRotation")
								: setup.storeClosed === undefined
									? storeModule
									: storeModuleClosingInto(setup.storeClosed),
				]),
		...(setup.federationFirst === false ? federation : []),
	];
	return createApp({
		modules,
		...(setup.background === undefined
			? {}
			: { overrideComponents: { federationGrantBackground: setup.background } }),
		bootstrapComponents: {
			config: {
				...makeValidCoreConfig(),
				...coreConfigForTests({
					// Configured only beside the module that handles its type, so no
					// composition here holds an enabled federation that nothing handles.
					...(setup.provider === null
						? {}
						: {
								federations: {
									upstream: {
										enabled: true,
										type: UPSTREAM_TYPE,
										callbackURL: "https://provider.example/federation/upstream/callback",
										issuer: "https://issuer.example",
										clientId: "cid",
									},
								},
							}),
					...(setup.withAudit === false ? {} : { declaredAbsent: ["auditSink"] }),
				}),
				rateLimit: { failMode: "closed" },
				...(setup.oldAuditDeclaration === true ? { audit: { sink: { type: "none" } } } : {}),
				"federation-grants": {
					enabled: setup.enabled ?? true,
					connections: setup.connections ?? { calendar: CONNECTION },
					...ACQUISITION_GRANT_SETTINGS,
					...(setup.grants ?? {}),
				},
			},
			pathResolver: (s: string) => s,
			clientRepository,
			...(setup.tokenSettingsIssuer === undefined
				? {}
				: {
						oauthTokenSettings: createTestOAuthTokenSettings({ issuer: setup.tokenSettingsIssuer }),
					}),
			...(() => {
				const { federationGrantIntentStore, userRepository, loginEntry, csrfGuard } =
					acquisitionComponents();
				return {
					...(setup.withIntentStore === false ? {} : { federationGrantIntentStore }),
					...(setup.withCsrfGuard === false
						? {}
						: {
								csrfGuard:
									setup.withCsrfGuard === "without-check"
										? { ...csrfGuard, check: undefined }
										: csrfGuard,
							}),
					...(setup.withLoginEntry === false
						? {}
						: {
								loginEntry:
									setup.withLoginEntry === "unconfigured" ? UNCONFIGURED_LOGIN_ENTRY : loginEntry,
							}),
					userRepository:
						setup.userRepository === "without-lookup"
							? { authenticate: async () => null, authenticateByToken: async () => null }
							: setup.userRepository === "bundled"
								? new InMemoryUserRepository(new Map())
								: userRepository,
				};
			})(),
			// Enabling a federation at all brings the session-federation stores
			// with it — a federation is first of all a way to log in, and that
			// guard is not this feature's. Present but empty: what is under test
			// here is the grant refusals, and nothing in this file logs anyone in.
			...SESSION_FEDERATION_STORES,
			...(setup.withUserSessionStore === false ? { userSessionStore: undefined } : {}),
			// The boundary a grant is compared against on every disclosure (the
			// federation-grants ADR, D13). Bundled here because every composition
			// that enables the feature needs one, which is the point of the
			// refusals below.
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

	it.each(["without-take", "without-refund"] as const)(
		"refuses to boot with a grant store %s, naming both rotation members",
		async (store) => {
			// A store without them keeps no rotation budget, or keeps every rotation
			// it took: refused here, not met as a storage outage at every refresh.
			await expect(boot({ store })).rejects.toThrow(/takeRotation.*refundRotation/s);
		},
	);

	it("boots with the rotation budget's settings written", async () => {
		const handle = await boot({ grants: { rotationBudget: 2, rotationWindow: "600" } });
		await handle.dispose();
	});

	it("refuses a rotation budget or window below one, naming the key", async () => {
		for (const [key, value] of [
			["rotationBudget", 0],
			["rotationBudget", "1.5"],
			["rotationWindow", 0],
			["rotationWindow", "an hour"],
		] as const) {
			const error = await boot({ grants: { [key]: value } }).then(
				() => undefined,
				(thrown: unknown) => thrown,
			);
			expect(error, `${key} ${value}`).toBeInstanceOf(BootError);
			const { issues } = (error as BootError).details as {
				issues: readonly { readonly path: readonly PropertyKey[] }[];
			};
			expect(
				issues.map((i) => i.path.join(".")),
				`${key} ${value}`,
			).toContain(`federation-grants.${key}`);
		}
	});

	it("refuses to boot with nowhere to keep grants", async () => {
		await expect(boot({ withStore: false })).rejects.toThrow(/federationGrantStore/);
	});

	it("refuses to boot with nothing that can end a grant", async () => {
		// The backstop, not a nicety: a grant outlives the session it was
		// agreed through, so the boundary is what reaches one on a replica that
		// never saw the withdrawal. A composition error belongs here, not in a
		// 503 per request.
		await expect(boot({ revocation: "absent" })).rejects.toThrow(/subjectRevocation component/);
	});

	it("refuses a revocation adapter with no grants boundary, naming grantsRevokedBefore", async () => {
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

	it("refuses a retrieval limit the promises cannot be kept under", async () => {
		// A lock that cannot outlive a refresh and its persistence lets two
		// replicas present the same refresh token (the federation-grants ADR, D12).
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
		await expect(boot({ provider: null })).rejects.toThrow(
			/federation-grants\.connections\.calendar: federation "upstream" is not configured/,
		);
	});

	it("refuses a federation whose adapter cannot act without the user", async () => {
		// An ordinary `refreshToken` renews a token inside a session with the
		// session's own credentials. It says nothing about whether this
		// provider may act for a user who is not present, which is the entire
		// question offline delegation asks.
		await expect(boot({ provider: sessionOnly })).rejects.toThrow(/delegated/);
		// And the pair without the code exchange, by name: the callback would
		// otherwise be the first place it failed, with a user standing in front
		// of it.
		await expect(boot({ provider: slice2Pair })).rejects.toThrow(/exchangeDelegatedCode/);
		// And one whose callback would arrive without the session cookie.
		await expect(boot({ provider: formPost })).rejects.toThrow(/form_post/);
	});

	it("refuses to discard every disclosure without being told to, naming core.declaredAbsent", async () => {
		await expect(boot({ withAudit: false })).rejects.toThrow(
			/list "auditSink" in core\.declaredAbsent/,
		);
	});

	it('does not take audit.sink.type = "none", where the declaration was, as the declaration', async () => {
		await expect(boot({ withAudit: false, oldAuditDeclaration: true })).rejects.toThrow(
			/core\.declaredAbsent/,
		);
	});

	it("boots with an empty connection map, because removing the last one is operable", async () => {
		const handle = await boot({ connections: {}, provider: null });
		await handle.dispose();
	});
});

describe("the cleanup allowance an enabled deployment registers", () => {
	it("is the refresh tail of the shipped budgets plus the margin: 45 seconds", async () => {
		const handle = await boot({});
		expect(handle.cleanupAllowanceMs).toBe(45_000);
		await handle.dispose();
	});

	it("grows with a raised budget", async () => {
		// The lock must outlive the raised hard timeout, or boot refuses first.
		const handle = await boot({
			grants: { upstreamHardTimeoutMs: 60_000, refreshLockTtlMs: 65_000 },
		});
		expect(handle.cleanupAllowanceMs).toBe(60_000 + 3_000 + 5_000 + 12_000);
		await handle.dispose();
	});

	it("is absent while the feature is off", async () => {
		const handle = await boot({ enabled: false });
		expect(handle.cleanupAllowanceMs).toBeUndefined();
		await handle.dispose();
	});

	it("is registered without draining a host-supplied registry that a failed boot never started", async () => {
		// The browser half refuses after the JSON half registered the tail.
		const background = createFederationGrantBackground();
		await expect(boot({ background, withCsrfGuard: false })).rejects.toThrow(/csrfGuard/);
		expect(background.closing).toBe(false);
		expect(background.admit()).toBeTypeOf("function");
	});

	it("does not make dispose wait on a host-supplied registry that nothing drained", async () => {
		const background = createFederationGrantBackground();
		const handle = await boot({ background });
		expect(handle.cleanupAllowanceMs).toBe(45_000);
		background.register(new Promise<void>(() => {}));
		const outcome = await Promise.race([
			handle.dispose().then(() => "disposed"),
			new Promise((resolve) => setTimeout(() => resolve("still waiting"), 50)),
		]);
		expect(outcome).toBe("disposed");
		expect(background.closing).toBe(false);
	});
});

describe("with the feature on, the drain", () => {
	it("runs ahead of the store's own cleanup", async () => {
		const order: string[] = [];
		const handle = await boot({ storeClosed: order });
		let persist!: () => void;
		handle.components.federationGrantBackground?.register(
			new Promise<void>((resolve) => {
				persist = () => resolve();
			}).then(() => {
				order.push("late write persisted");
			}),
		);

		const disposed = handle.dispose();
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(order).toEqual([]);
		persist();
		await disposed;
		expect(order).toEqual(["late write persisted", "store closed"]);
	});
});

describe("the actions it registers", () => {
	it("registers the browser half's three actions, graded use", async () => {
		const handle = await boot({});
		try {
			const resolver = handle.components.sessionRequirementResolver;
			expect(
				[
					"federation_grants.connect",
					"federation_grants.consent",
					"federation_grants.callback",
				].map((name) => resolver?.action(name)),
			).toEqual([
				{ name: "federation_grants.connect", grade: "use" },
				{ name: "federation_grants.consent", grade: "use" },
				{ name: "federation_grants.callback", grade: "use" },
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("registers none of them while the feature is off: the switched-off module registers nothing", async () => {
		const handle = await boot({
			enabled: false,
			withStore: false,
			withLimiter: false,
			withAudit: false,
			provider: null,
		});
		try {
			expect(
				handle.components.sessionRequirementResolver?.action("federation_grants.connect"),
			).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("exports none of them: the router that admits them is mounted by the module alone", async () => {
		const entry = await import("#/index.mjs");
		expect(Object.hasOwn(entry, "FEDERATION_GRANTS_ADMISSION_ACTIONS")).toBe(false);
	});
});

describe("leaving the feature off", () => {
	it('reads the spellings an environment variable arrives in, so "true" enables', async () => {
		// HOCON substitutes `${?FEDERATION_GRANTS_ENABLED}` as a string,
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
		const issue = issues.find((i) => i.path.join(".") === "federation-grants.enabled");
		expect(issue?.message).toMatch(/"true", "false", "1" or "0"/);
	});
});

describe("what creating a grant needs", () => {
	it("refuses a deployment with no consent page, before a user could reach one that is not there", async () => {
		await expect(boot({ grants: { consent: {} } })).rejects.toThrow(
			/federation-grants\.consent\.url/,
		);
	});

	it("holds every connection's callback to the origin of the oauthTokenSettings issuer, over the configuration's", async () => {
		// The callbacks are written on the configuration's issuer; the slot names
		// another origin, so they are no longer on the provider's own.
		await expect(boot({ tokenSettingsIssuer: "https://slot.test" })).rejects.toThrow(
			/callbackURL must be on the provider's own origin \(https:\/\/slot\.test\)/,
		);
	});

	it("refuses a connection with no callback of its own", async () => {
		const { callbackURL: _none, ...withoutCallback } = CONNECTION;
		await expect(boot({ connections: { calendar: withoutCallback } })).rejects.toThrow(
			/connections\.calendar\.callbackURL/,
		);
	});

	it("refuses a deployment with no durable sessions for the connect flow to re-read", async () => {
		await expect(boot({ withUserSessionStore: false })).rejects.toThrow(
			/federationGrantsModule: federation grants are enabled and no userSessionStore/,
		);
	});

	it("refuses a deployment with no login page to send a browser that is not signed in to", async () => {
		// Core's schema takes an empty page and only oauthModule requires one;
		// this composition has no oauthModule. The page is the session
		// module's `loginEntry`, which is built without one and fails where it
		// is read: here, at boot, rather than as a 500 for every such browser.
		await expect(boot({ withLoginEntry: "unconfigured" })).rejects.toThrow(
			/the loginEntry slot names no login page/,
		);
	});

	it("refuses a deployment with no loginEntry, naming the component", async () => {
		// Connect sends a browser that is not signed in to the login page
		// through the `loginEntry` slot the session module provides;
		// enabled without it, the flow's first page would answer a 500.
		await expect(boot({ withLoginEntry: false })).rejects.toThrow(
			/federation grants are enabled and no loginEntry is installed/,
		);
	});

	it("boots disabled without a loginEntry: a deployment that leaves grants off owes nothing", async () => {
		const handle = await boot({ enabled: false, withLoginEntry: false });
		await handle.dispose();
	});

	it("refuses a deployment with no csrfGuard, naming the component", async () => {
		// The consent answer is held to the deployment's CSRF policy, the
		// `csrfGuard` slot the session module provides; enabled without it, the
		// answer would have no request-origin check at all.
		await expect(boot({ withCsrfGuard: false })).rejects.toThrow(
			/federation grants are enabled and no csrfGuard is installed/,
		);
	});

	it("refuses a csrfGuard with no check to ask, naming it", async () => {
		await expect(boot({ withCsrfGuard: "without-check" })).rejects.toThrow(
			/the csrfGuard installed has no check/,
		);
	});

	it("boots disabled without a csrfGuard: a deployment that leaves grants off owes nothing", async () => {
		const handle = await boot({ enabled: false, withCsrfGuard: false });
		await handle.dispose();
	});

	it("refuses a deployment with nowhere to lodge an intent", async () => {
		await expect(boot({ withIntentStore: false })).rejects.toThrow(/federationGrantIntentStore/);
	});

	it("refuses a required identity lookup the repository cannot answer, and boots once it is recorded as unsupported", async () => {
		await expect(boot({ userRepository: "without-lookup" })).rejects.toThrow(
			/findSubjectByFederatedIdentity/,
		);
		const handle = await boot({
			userRepository: "without-lookup",
			grants: { identityLookup: "unsupported" },
		});
		await handle.dispose();
	});

	it("refuses the bundled repository beside a connection, and boots once the deployment records it does not ask", async () => {
		await expect(boot({ userRepository: "bundled" })).rejects.toThrow(
			/connections\.calendar[\s\S]*identityLookup = "unsupported"/,
		);
		const handle = await boot({
			userRepository: "bundled",
			grants: { identityLookup: "unsupported" },
		});
		await handle.dispose();
	});

	it("asks none of it of a deployment that has not enabled the feature", async () => {
		const handle = await boot({
			enabled: false,
			withIntentStore: false,
			userRepository: "without-lookup",
			grants: { consent: {} },
		});
		await handle.dispose();
	});
});
