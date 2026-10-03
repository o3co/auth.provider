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
 * The two manifests this package installs. Why a package of its own rather than `/oauth/token`
 * is recorded in `packages/core/docs/adr/2026-09-17-federation-grants-offline-delegation.md`.
 *
 * Two modules, because their dependency edges point different ways:
 * `federationGrantBackgroundModule` provides the registry a shutdown drains,
 * built *after* the store, the revocation boundary and the sink so that its
 * cleanup runs *before* theirs; `federationGrantsModule` mounts the routes and
 * requires it. Install both through {@link federationGrantsModules}; routes
 * without the registry are a boot refusal.
 *
 * `federation-grants.enabled = false` in the package's `reference.conf`:
 * installing the package does not turn on offline delegation. The key is the
 * routes module's switch (`section.isEnabled`): off, the module registers
 * nothing — no route, admission action or rate-limit prefix — and reads none
 * of the feature's configuration or components.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	checkOAuthTokenSettings,
	coerceBooleanFromEnv,
	defineModule,
	describeAbsenceDeclaration,
	durationFromEnv,
	type FederationGrantConnection,
	type FederationGrantRefresher,
	isAbsenceDeclared,
	type ProviderDeps,
	requireFederationGrantSubjectRevocation,
	resolveFederationGrantAcquisitionLimits,
	resolveFederationGrantRetrievalLimits,
	type SupportsSessionsOnlyRevocation,
	supportsDelegatedAuthorization,
	type UserSessionStore,
	wholeNumberFromEnv,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import {
	requireFederationGrantIdentityLookup,
	requireFederationGrantIntentStore,
	resolveFederationGrantAcquisitionSettings,
} from "./acquisitionSettings.mjs";
import { FEDERATION_GRANTS_ADMISSION_ACTIONS } from "./admissionActions.mjs";
import { createFederationGrantBackground, federationGrantsCleanupTailMs } from "./background.mjs";
import {
	createFederationGrantBrowserRouter,
	FEDERATION_GRANTS_BROWSER_MOUNT_PATH,
	FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX,
	type FederationGrantDelegatedAuthorizer,
} from "./browserRoutes.mjs";
import { resolveFederationGrantConnections } from "./connections.mjs";
import { createFederationGrantRouter, FEDERATION_GRANTS_RATE_LIMIT_PREFIX } from "./routes.mjs";
import { FEDERATION_GRANTS_MOUNT_PATH } from "./types.mjs";

/** A duration in whole units, read strictly from a number or a variable's decimal string. */
const duration = (bounds: z.ZodNumber) => durationFromEnv(bounds).optional();

/** What a grant may be for: one entry of `federation-grants.connections`. Strict. */
const connectionSchema = z
	.object({
		federation: z.string().min(1),
		scopes: z.array(z.string().min(1)).min(1),
		resource: z.string().min(1).optional(),
		// No default for either: a guessed access-token maximum invents a
		// residual-access policy, and a guessed boundary silently shares one.
		boundary: z.string().min(1),
		maxAccessTokenLifetime: durationFromEnv(z.number().int().positive()),
		allowScopeSubsets: coerceBooleanFromEnv.optional(),
		authorizationParams: z.record(z.string(), z.string()).optional(),
		callbackURL: z.string().min(1).optional(),
		// Verified id_token claims handed to the Store beside the subject for
		// the linked-account check. Names only; the package checks them.
		identityClaims: z.array(z.string()).optional(),
	})
	.strict();

/**
 * The schema of `federation-grants {}`, the module's own section, strict at
 * every level; each leaf reads the string a variable carries. Bounds live
 * where the values are used (`resolveFederationGrantRetrievalLimits` and the
 * acquisition settings); the defaults in the package's `reference.conf`.
 */
export const federationGrantsConfigSchema = z
	.object({
		enabled: coerceBooleanFromEnv.optional(),
		// Seconds. A new grant's lifetime, and the most an operator permits;
		// the code's one-year ceiling still applies above it.
		defaultExpiresIn: duration(z.number().int().positive()),
		maxExpiresIn: duration(z.number().int().positive()),
		// Seconds. The retrieval's timings.
		refreshBuffer: duration(z.number().int().nonnegative()),
		ineligibleRetryAfter: duration(z.number().int().positive()),
		refreshFailureBackoff: duration(z.number().int().nonnegative()),
		// Milliseconds, as the limits they become are.
		upstreamTimeoutMs: duration(z.number().int().positive()),
		upstreamHardTimeoutMs: duration(z.number().int().positive()),
		refreshLockTtlMs: duration(z.number().int().positive()),
		lockWaitMs: duration(z.number().int().nonnegative()),
		persistRetryBudgetMs: duration(z.number().int().positive()),
		// The rotation budget: upstream refresh-token rotations a grant may
		// take in a window, and the window in seconds.
		rotationBudget: wholeNumberFromEnv(z.number().int().positive()).optional(),
		rotationWindow: duration(z.number().int().positive()),
		// Whether a subject-wide revocation may be asked to leave this subject's
		// established grants standing: an allowance the caller must use.
		allowKeepOnSubjectRevocation: coerceBooleanFromEnv.optional(),
		identityLookup: z.enum(["required", "unsupported"]).optional(),
		consent: z
			.object({ url: z.string().min(1).optional() })
			.strict()
			.optional(),
		// An empty map is valid: removing the last connection must remain an
		// operable change.
		connections: z.record(z.string().min(1), connectionSchema).optional(),
	})
	.strict()
	.optional();

/** A path in the section no variable binds: its relocation names none. */
const unbound = (to: string) => ({ to, environmentVariable: null }) as const;

const REQUIRES = [
	"config",
	"federationGrantBackground",
	"clientRepository",
	// The synthetic key every consumer of session admission takes: the browser
	// half admits the browser's session through it at every step. Always
	// present — the planner fills it.
	"sessionRequirementResolver",
] as const;
const OPTIONAL = [
	"federationGrantStore",
	"rateLimiter",
	"auditSink",
	"subjectRevocation",
	"replaySeenSet",
	"logger",
	"federationProviders",
	"federationGrantIntentStore",
	"userRepository",
	"userSessionStore",
	// The login page connect sends a browser that is not signed in to, which
	// the session module provides: required once grants are enabled.
	"loginEntry",
	// The deployment's CSRF policy the consent answer is held to, which the
	// session module provides: required once grants are enabled
	// (`requireCsrfGuard`).
	"csrfGuard",
	// What the oauth module provides of `oauth {}`: the issuer every route
	// and the acquisition settings are built on. Read from the configuration
	// when no module provides it.
	"oauthTokenSettings",
	// Where an enabled deployment registers the drain's tail.
	"lifecycleRegistrar",
] as const;

/**
 * The deps every contribution of {@link federationGrantsModule} receives:
 * exactly its `requires` / `optional`, typed. Every `require*`
 * helper below is the presence check for one optional slot.
 */
type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
export type FederationGrantsModuleDeps = ProviderDeps<
	Requires,
	Optional,
	typeof federationGrantsConfigSchema
>;

/**
 * The issuer the routes and the acquisition settings are built on: the
 * `oauthTokenSettings` slot's when the composition holds it, the slot
 * read whole and checked first, otherwise `oauth.jwt.issuer` as the
 * configuration carries it.
 */
const issuerOf = (deps: FederationGrantsModuleDeps): string =>
	deps.oauthTokenSettings === undefined
		? deps.config.oauth.jwt.issuer
		: checkOAuthTokenSettings(deps.oauthTokenSettings, deps.config).issuer;

/**
 * An enabled deployment with nowhere to keep grants would
 * authenticate a client and then answer 503 to everything, having accepted
 * `enabled = true` as if it meant something. A store without the rotation
 * budget's members (one written against an earlier port, or in plain
 * JavaScript) would answer 503 to every refresh instead.
 */
const requireStore = (
	deps: FederationGrantsModuleDeps,
): NonNullable<FederationGrantsModuleDeps["federationGrantStore"]> => {
	const store = deps.federationGrantStore;
	if (store === undefined) {
		throw new Error(
			"federationGrantsModule: federation-grants.enabled = true requires a " +
				"federationGrantStore component. A grant is a user's standing consent that " +
				"outlives their session, so there is nowhere to read one from and nothing to " +
				"write a rotated credential back to without it. Install the bundled memory " +
				"store (single replica only) or an adapter such as " +
				"redisFederationGrantStoreModule.",
		);
	}
	const members: Partial<typeof store> = store;
	if (typeof members.takeRotation !== "function" || typeof members.refundRotation !== "function") {
		throw new Error(
			"federationGrantsModule: the federationGrantStore component does not implement " +
				"takeRotation and refundRotation, which the FederationGrantStore port requires. " +
				"They keep the per-grant rotation budget that bounds upstream refresh-token " +
				"rotations; implement both, or install the bundled memory store (single replica " +
				"only) or redisFederationGrantStoreModule.",
		);
	}
	return store;
};

/**
 * Both routes are throttled before client authentication, so
 * that repeated unauthenticated hits are bounded before they reach a
 * repository lookup — and what happens when the limiter backend is down is the
 * limiter's own policy (`RateLimiter.failMode`), not this module's to choose.
 */
const requireLimiter = (
	deps: FederationGrantsModuleDeps,
): NonNullable<FederationGrantsModuleDeps["rateLimiter"]> => {
	if (deps.rateLimiter === undefined) {
		throw new Error(
			"federationGrantsModule: federation-grants.enabled = true requires a rateLimiter " +
				"component. These routes take an opaque grant id in the path and answer the " +
				"same 404 for an unknown one, for another client's and for another subject's " +
				"— which is only a defence while the number of guesses is bounded.",
		);
	}
	return deps.rateLimiter;
};

/**
 * Can this deployment act on each connection for a user who is not present?
 * The provider must be contributed and have ALL THREE delegated methods (the
 * authorization URL, the connect callback's code exchange, the refresh). An
 * ordinary `refreshToken` is not enough: it refreshes a session's token with
 * the session's own credentials.
 *
 * Resolved in the route contribution phase rather than while components are
 * materialised: named federation contributions are assembled first, and
 * checking the synthetic map earlier would refuse a configuration whose
 * provider simply had not been contributed yet.
 */
const requireDelegatedCapability = (
	deps: FederationGrantsModuleDeps,
	connections: ReadonlyMap<string, FederationGrantConnection>,
): void => {
	const providers = deps.federationProviders;
	for (const connection of connections.values()) {
		const provider = providers?.get(connection.federation);
		if (provider === undefined) {
			throw new Error(
				`federationGrantsModule: federation-grants.connections.${connection.name} names the ` +
					`federation "${connection.federation}", which no installed module contributes. ` +
					"A connection whose provider is absent can never be refreshed, and a grant on " +
					"it would be created and then fail every time it is spent.",
			);
		}
		if (!supportsDelegatedAuthorization(provider)) {
			throw new Error(
				`federationGrantsModule: the federation "${connection.federation}", named by ` +
					`federation-grants.connections.${connection.name}, has no delegated ` +
					"authorization capability. Offline delegation needs ALL THREE of " +
					"`buildDelegatedAuthorizationUrl`, `exchangeDelegatedCode` and " +
					"`refreshDelegatedToken` — an adapter written against the earlier pair lacks the " +
					"exchange the connect callback makes. An ordinary `refreshToken` renews a token " +
					"inside a session and says nothing about acting for a user who is not present.",
			);
		}
		// The connect callback proves whose grant it is from the browser's
		// session, and a `form_post` callback arrives as a cross-site POST without
		// the session cookie. No bundled adapter with the capability declares it;
		// a custom one may.
		if (provider.responseMode === "form_post") {
			throw new Error(
				`federationGrantsModule: the federation "${connection.federation}", named by ` +
					`federation-grants.connections.${connection.name}, declares response_mode=form_post. ` +
					"The connect callback proves whose grant it is from the browser's session, and a " +
					"form_post callback arrives without the session cookie.",
			);
		}
	}
};

/**
 * The audit sink is optional to wire, not optional to decide — here for the
 * events an operator needs most: every disclosure of a credential that works
 * while nobody is watching. The message is built from the shared policy so it
 * cannot drift from every other module's for the same slot.
 */
const requireAuditDecision = (deps: FederationGrantsModuleDeps): void => {
	if (deps.auditSink !== undefined) return;
	if (isAbsenceDeclared(deps.config, AUDIT_SINK_ABSENCE_POLICY)) return;
	throw new Error(
		"federationGrantsModule: federation-grants.enabled = true with no auditSink component. " +
			`Wire one, or ${describeAbsenceDeclaration(AUDIT_SINK_ABSENCE_POLICY)} to declare the ` +
			`capability absent on purpose. ${AUDIT_SINK_ABSENCE_POLICY.hint}`,
	);
};

/** The authorizer the connect flow sends a user upstream with: the connection's provider's. */
const authorizerFor =
	(deps: FederationGrantsModuleDeps) =>
	(federation: string): FederationGrantDelegatedAuthorizer | undefined => {
		const provider = deps.federationProviders?.get(federation);
		if (!supportsDelegatedAuthorization(provider)) return undefined;
		return provider;
	};

/**
 * The connect flow re-reads the durable session behind the cookie at every
 * step — through session admission, which reads the store the module hands
 * it — so a deployment that creates grants needs the store it lives in. Every
 * deployment that enables a federation already has one — the federation
 * guard asks for it — and this says why this feature needs it too.
 */
const requireUserSessionStore = (deps: FederationGrantsModuleDeps): UserSessionStore => {
	const store = deps.userSessionStore;
	if (store === undefined) {
		throw new Error(
			"federationGrantsModule: federation grants are enabled and no userSessionStore is installed. " +
				"The connect flow proves whose grant it is from the durable session behind the browser's " +
				"cookie, and re-reads it before the consent is shown, answered, and activated",
		);
	}
	return store;
};

/**
 * The `csrfGuard` slot the session module provides — the policy
 * `/session/login` runs. The consent answer is a state change made with the
 * browser's session cookie: it spends the question and sends the user
 * upstream. Without the guard, or with one that has no `check`, it would have
 * no request-origin check at all.
 */
const requireCsrfGuard = (
	deps: FederationGrantsModuleDeps,
): NonNullable<FederationGrantsModuleDeps["csrfGuard"]> => {
	const guard = deps.csrfGuard;
	if (guard === undefined) {
		throw new Error(
			"federationGrantsModule: federation grants are enabled and no csrfGuard is installed. " +
				"POST /session/federation-grants/consent, the user's answer, is made with the browser's " +
				"session cookie and is held to the deployment's CSRF policy — the one /session/login runs, " +
				"an Origin/Referer check against session.csrf.trustedOrigins and a signed double-submit " +
				"token — through the csrfGuard slot the session module (sessionModule) provides. " +
				"Install the session module, fill the csrfGuard slot with a guard of your own that keeps " +
				"core's CsrfGuard contract, or leave federation grants disabled.",
		);
	}
	if (typeof guard.check !== "function") {
		throw new Error(
			"federationGrantsModule: the csrfGuard installed has no check function, which the consent " +
				"answer asks. Install the session module's guard (sessionModule), or one that keeps core's " +
				"CsrfGuard contract.",
		);
	}
	return guard;
};

/** The refresher core calls: the connection's provider, or nothing for one that lost its capability. */
const refresherFor =
	(deps: FederationGrantsModuleDeps) =>
	(connection: FederationGrantConnection): FederationGrantRefresher | undefined => {
		const provider = deps.federationProviders?.get(connection.federation);
		if (!supportsDelegatedAuthorization(provider)) return undefined;
		return { refreshDelegatedToken: (params) => provider.refreshDelegatedToken(params) };
	};

/**
 * The subject's grants boundary: `grantsRevokedBefore`, deliberately not
 * `revokedBefore`. The two move independently: a subject-wide revocation
 * asked to keep this subject's grants advances the sessions boundary alone,
 * and reading that one here would revoke the grants the policy chose to keep.
 *
 * The adapter is the one the boot refusal returned, so the capability is
 * present; the answer is still validated, because boot cannot establish what
 * a backend will say about a subject that does not exist yet.
 */
const boundaryFor =
	(revocation: SupportsSessionsOnlyRevocation): ((subject: string) => Promise<Date | null>) =>
	async (subject) => {
		const watermark = await revocation.grantsRevokedBefore(subject);
		// The port says `Date | null`, and a `null` is a STATEMENT: nothing was
		// revoked for this subject. An adapter that answers `undefined` — or
		// anything else — has made no statement at all, and reading it as one
		// would silently switch the backstop off for that subject. `/status` and
		// `/token` both read the contract here.
		if (watermark === null) return null;
		if (watermark instanceof Date && !Number.isNaN(watermark.getTime())) return watermark;
		throw new Error(
			"federationGrantsModule: the subjectRevocation adapter answered something that is " +
				"neither a date nor null for the subject's grants boundary. Fails closed: an " +
				"answer that cannot be compared is not the same as no revocation.",
		);
	};

export const federationGrantBackgroundModule = defineModule({
	name: "federation-grant-background",
	/**
	 * Not read: they order the build. `dispose()` runs component cleanups in
	 * reverse build order, so the registry's drain precedes the cleanup of what
	 * it writes *through* (a rotated refresh token into the store, an audit event
	 * into the sink); an adapter that closed its client first would fail the
	 * write the drain waits for. `optional`, not `requires`, so a deployment with
	 * the feature off still boots without them; an optional key produces the
	 * same ordering edge whenever a *module* fills it. A slot filled from
	 * `bootstrapComponents` is the host's own, neither ordered nor disposed of.
	 */
	optional: ["federationGrantStore", "subjectRevocation", "auditSink"] as const,
	provides: {
		federationGrantBackground: () => createFederationGrantBackground(),
	},
	lifecycle: {
		federationGrantBackground: {
			cleanup: (background) => background.drain(),
		},
	},
});

export const federationGrantsModule = defineModule<
	Requires,
	Optional,
	typeof federationGrantsConfigSchema
>({
	name: "federation-grants",
	// Each of the section's own keys moved from `federationGrants`; the grant
	// stores' keys there (their key ring, retention) are relocated by the
	// stores, so the old section is not relocated whole.
	section: {
		schema: federationGrantsConfigSchema,
		reference: new URL("../config/reference.conf", import.meta.url),
		relocatedFrom: {
			"federationGrants.enabled": "enabled",
			"federationGrants.defaultExpiresIn": unbound("defaultExpiresIn"),
			"federationGrants.maxExpiresIn": unbound("maxExpiresIn"),
			"federationGrants.refreshBuffer": unbound("refreshBuffer"),
			"federationGrants.ineligibleRetryAfter": unbound("ineligibleRetryAfter"),
			"federationGrants.refreshFailureBackoff": unbound("refreshFailureBackoff"),
			"federationGrants.upstreamTimeoutMs": unbound("upstreamTimeoutMs"),
			"federationGrants.upstreamHardTimeoutMs": unbound("upstreamHardTimeoutMs"),
			"federationGrants.refreshLockTtlMs": unbound("refreshLockTtlMs"),
			"federationGrants.lockWaitMs": unbound("lockWaitMs"),
			"federationGrants.persistRetryBudgetMs": unbound("persistRetryBudgetMs"),
			"federationGrants.allowKeepOnSubjectRevocation": "allowKeepOnSubjectRevocation",
			"federationGrants.identityLookup": "identityLookup",
			"federationGrants.consent": unbound("consent"),
			"federationGrants.consent.url": "consent.url",
			"federationGrants.connections": unbound("connections"),
		},
		isEnabled: (section) => section?.enabled === true,
	},
	requires: REQUIRES,
	optional: OPTIONAL,
	contributes: {
		// What the browser half admits.
		admissionActions: FEDERATION_GRANTS_ADMISSION_ACTIONS,
		// The prefixes both routers limit under, claimed with no budget of their
		// own.
		rateLimitBudgets: {
			[FEDERATION_GRANTS_RATE_LIMIT_PREFIX]: () => null,
			[FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX]: () => null,
		},
		routes: [
			(deps: FederationGrantsModuleDeps) => {
				// In this order, so that the most fundamental omission is the one
				// an operator is told about: a deployment with no store has not
				// half-configured the feature, it has not configured it.
				const store = requireStore(deps);
				// Second, because it is the same question asked of the other
				// half: a grant that can be read from somewhere and ended
				// nowhere is worse than one that cannot be read at all. A
				// composition error belongs at boot, before a user is told the
				// deployment was set up.
				const revocation = requireFederationGrantSubjectRevocation({
					module: "federationGrantsModule",
					subjectRevocation: deps.subjectRevocation,
					federationGrantStore: store,
				});
				const rateLimiter = requireLimiter(deps);
				const limits = resolveFederationGrantRetrievalLimits(deps.section);
				const connections = resolveFederationGrantConnections(deps.section, deps.config);
				requireDelegatedCapability(deps, connections);
				requireAuditDecision(deps);
				// What creating a grant needs, refused here rather than at the end
				// of somebody's consent: the consent page, a callback per connection
				// on the provider's own origin, somewhere to lodge an intent, and —
				// unless the deployment records that it has none — the identity lookup.
				const acquisition = resolveFederationGrantAcquisitionSettings(
					deps.section,
					connections,
					deps.loginEntry,
					{ issuer: issuerOf(deps) },
				);
				const intentStore = requireFederationGrantIntentStore(deps.federationGrantIntentStore);
				requireFederationGrantIdentityLookup(
					acquisition.identityLookup,
					deps.userRepository,
					connections,
				);
				const lifetimes = resolveFederationGrantAcquisitionLimits(deps.section);
				// The drain's allowance, for a host that bounds dispose(). The component
				// cleanup runs the drain, ahead of the store; this waits only on a drain
				// already started, never on a registry the host supplied.
				const background = deps.federationGrantBackground;
				deps.lifecycleRegistrar?.register(
					() => (background.closing ? background.drain() : Promise.resolve()),
					{ tailMs: federationGrantsCleanupTailMs(limits) },
				);
				return {
					id: "federation-grants",
					mountPath: FEDERATION_GRANTS_MOUNT_PATH,
					handler: createFederationGrantRouter({
						store,
						connections,
						refresher: refresherFor(deps),
						grantsBoundary: boundaryFor(revocation),
						limits,
						background: deps.federationGrantBackground,
						acquisition: {
							intentStore,
							connections: acquisition.connections,
							limits: lifetimes,
						},
						clientRepository: deps.clientRepository,
						issuer: issuerOf(deps),
						rateLimiter,
						...(deps.replaySeenSet === undefined ? {} : { replaySeenSet: deps.replaySeenSet }),
						...(deps.auditSink === undefined ? {} : { auditSink: deps.auditSink }),
						...(deps.logger === undefined ? {} : { logger: deps.logger }),
					}),
				};
			},
			// The browser half — connect and consent — under `/session`.
			// Its own contribution because it must mount AFTER the session
			// middleware: it reads `req.session`, and a declaration-order accident
			// would hand it a request with none, which reads as "not signed in"
			// and sends a signed-in user to the login page. `after` makes a
			// composition without the middleware a boot error instead.
			(deps: FederationGrantsModuleDeps) => {
				// The JSON contribution has already refused everything shared —
				// no store, no boundary, no consent page, no intent store — in the
				// order an operator should hear it; this only asks what the
				// browser half needs besides.
				const store = requireStore(deps);
				const revocation = requireFederationGrantSubjectRevocation({
					module: "federationGrantsModule",
					subjectRevocation: deps.subjectRevocation,
					federationGrantStore: store,
				});
				const connections = resolveFederationGrantConnections(deps.section, deps.config);
				const acquisition = resolveFederationGrantAcquisitionSettings(
					deps.section,
					connections,
					deps.loginEntry,
					{ issuer: issuerOf(deps) },
				);
				const limits = resolveFederationGrantRetrievalLimits(deps.section);
				return {
					id: "federation-grants-browser",
					mountPath: FEDERATION_GRANTS_BROWSER_MOUNT_PATH,
					after: ["session-middleware"],
					handler: createFederationGrantBrowserRouter({
						intentStore: requireFederationGrantIntentStore(deps.federationGrantIntentStore),
						grantStore: store,
						clientRepository: deps.clientRepository,
						userSessionStore: requireUserSessionStore(deps),
						// Where session admission reads the SESSIONS boundary — what a
						// session must have authenticated after — and the
						// requirements it asks. Not the grants boundary, which the
						// callback reads through `grantsBoundary`.
						subjectRevocation: revocation,
						requirements: deps.sessionRequirementResolver,
						revocationSkewMs: limits.revocationSkewMs,
						connections: acquisition.connections,
						authorizerFor: authorizerFor(deps),
						consentUrl: acquisition.consentUrl,
						login: acquisition.login,
						csrfGuard: requireCsrfGuard(deps),
						issuer: issuerOf(deps),
						rateLimiter: requireLimiter(deps),
						background: deps.federationGrantBackground,
						// The GRANTS boundary, for the callback's backstop and re-read.
						grantsBoundary: boundaryFor(revocation),
						identityLookup: acquisition.identityLookup,
						...(deps.userRepository === undefined ? {} : { userRepository: deps.userRepository }),
						upstreamTimeoutMs: limits.upstreamHardTimeoutMs,
						...(deps.auditSink === undefined ? {} : { auditSink: deps.auditSink }),
						...(deps.logger === undefined ? {} : { logger: deps.logger }),
					}),
				};
			},
		],
	},
});

/**
 * The documented installation form: `modules: [...federationGrantsModules]`.
 * The registry first, though the planner would sort them anyway — reading it
 * in dependency order is how the pair explains itself at a composition root.
 */
export const federationGrantsModules = [
	federationGrantBackgroundModule,
	federationGrantsModule,
] as const;
