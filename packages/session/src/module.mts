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

import {
	type AppConfig,
	AUDIT_SINK_ABSENCE_POLICY,
	type CsrfGuard,
	type CsrfTokenSigner,
	consoleLogger,
	defineModule,
	fullSectionsSchema,
	type Logger,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import express from "express";
import {
	createCsrfProtectionFromConfig,
	createSessionCsrfGuard,
	type SessionCsrfConfigSlice,
} from "./csrf.mjs";
import { extractFederationSection } from "./federations/extract-federation-section.mjs";
import { deriveFederationTransactionCookieName } from "./federations/transaction.mjs";
import { loginEntryFromConfig } from "./login-entry.mjs";
import { LOGIN_RATE_LIMIT_PREFIX, readLoginRateLimitBudget } from "./loginBudget.mjs";
import * as federationRoutes from "./routes/Federation.mjs";
import * as sessionRoutes from "./routes/Session.mjs";

const sessionConfigSchema = fullSectionsSchema.pick({
	session: true,
	rateLimit: true,
	federations: true,
	endpoints: true,
	cors: true,
});

/**
 * Boot-time projection of `config.federations` to a `name → callbackURL`
 * map. Throws when an enabled federation has no `callbackURL`: a deployment
 * misconfiguration fails at boot, not per request.
 */
function deriveProviderCallbackUrls(
	federations: Record<string, unknown>,
): ReadonlyMap<string, string> {
	const out = new Map<string, string>();
	for (const name of Object.keys(federations)) {
		const slice = extractFederationSection(federations, name);
		if (!slice) continue; // disabled or absent — skip
		const callbackURL = slice.callbackURL;
		if (typeof callbackURL !== "string" || callbackURL.length === 0) {
			throw new Error(`federations.${name}: callbackURL is required when federation is enabled`);
		}
		out.set(name, callbackURL);
	}
	return out;
}

/**
 * The `csrfGuard` slot's value: the signed double-submit token of
 * `createCsrfProtectionFromConfig` (cookie `<session.name>.csrf`, signed
 * through `signer`) plus `session.csrf.trustedOrigins`. The session routes
 * build their own `CsrfProtection` over the same signer, so each accepts the
 * other's tokens: the token is signed, not stored.
 */
const csrfGuardOf = (config: AppConfig, signer: CsrfTokenSigner, logger: Logger): CsrfGuard => {
	const session = config.session as unknown as SessionCsrfConfigSlice;
	return createSessionCsrfGuard({
		csrf: createCsrfProtectionFromConfig(session, { signer }),
		trustedOrigins: session.csrf?.trustedOrigins ?? [],
		logger,
	});
};

/**
 * The session and federation route surface, as a pre-built `Module` (pass it
 * to the manifest directly; its dependencies come from sibling modules).
 *
 * Routes, both under `/session`:
 *   - "session-routes"    — GET /session/csrf, POST /session/login,
 *                           POST /session/logout
 *   - "federation-routes" — GET /session/oauth/federation/:name (+ callback)
 *
 * `requires`: `config` and `userRepository`; the three stores these routes
 * use (`userSessionStore`, `federationTokenStore`, `sessionFederationIndex`);
 * `csrfTokenSigner`, what the CSRF token is signed and checked with (the
 * session store's module provides it from `session.secret`, which this module
 * never reads); and the planner-derived `federationProviders`,
 * `federationRedirectPolicyResolver` and `sessionRequirementResolver`
 * (password login and the federation link routes go through admission), and
 * `deploymentMode` (the login throttle's per-process fallback is refused
 * under `multi`, so a mode read as absent must not lift that).
 *
 * `provides` what other packages need of the browser session through
 * core-owned slot contracts, so none imports this package: `csrfGuard` and
 * `loginEntry`. `providerCallbackUrls` is derived from config inside the
 * federation-routes lambda rather than being a synthetic key, since it has no
 * contribution surface.
 */
export const sessionModule = defineModule<
	| "config"
	| "userRepository"
	| "userSessionStore"
	| "federationTokenStore"
	| "sessionFederationIndex"
	| "csrfTokenSigner"
	| "federationProviders"
	| "federationRedirectPolicyResolver"
	| "sessionRequirementResolver"
	| "deploymentMode",
	"logger" | "rateLimiter" | "auditSink" | "subjectSessionIndex" | "subjectRevocation"
>({
	name: "session",
	configSchema: sessionConfigSchema,
	requires: [
		"config",
		"userRepository",
		"userSessionStore",
		"federationTokenStore",
		"sessionFederationIndex",
		"csrfTokenSigner",
		"federationProviders",
		"federationRedirectPolicyResolver",
		"sessionRequirementResolver",
		"deploymentMode",
	],
	// All optional so a composition without them still boots: without
	// `rateLimiter` the router uses a per-process in-memory limiter (and
	// warns); without `auditSink` no events are emitted; without
	// `subjectSessionIndex`, `revokeAllForSubject` reports the capability as
	// unavailable; `subjectRevocation` is the boundary the link routes'
	// admission reads when wired.
	optional: ["logger", "rateLimiter", "auditSink", "subjectSessionIndex", "subjectRevocation"],
	// Optional to wire, not optional to decide: an unfilled `auditSink` must be
	// declared (`audit.sink.type = "none"`), and absent subject-level
	// revocation must be declared (`oauth.revocation.subject = "unsupported"`),
	// or a credential change would silently invalidate nothing. One constant on
	// both revocation keys: every module's policy on a key must agree, and the
	// two slots are one capability.
	absencePolicies: {
		auditSink: AUDIT_SINK_ABSENCE_POLICY,
		subjectSessionIndex: SUBJECT_REVOCATION_ABSENCE_POLICY,
		subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
	},
	// What this module owns of the browser session that other packages use,
	// as slots whose contracts are core's: a package imports only core and
	// requires the slot instead of rebuilding the policy from configuration.
	provides: {
		// The one CSRF policy: the guard `/session/login` runs, over the same
		// signer, cookie and trust list, so a token `GET /session/csrf` hands out
		// is accepted wherever the slot is mounted (`csrfGuardOf`).
		csrfGuard: (deps) =>
			csrfGuardOf(deps.config as AppConfig, deps.csrfTokenSigner, deps.logger ?? consoleLogger),
		// The login page (`endpoints.login.url`) and the `redirect_to` protocol
		// `/authorize` and the federation-grants connect flow send a browser
		// there by. Built with no page configured, failing where it is read.
		loginEntry: (deps) => loginEntryFromConfig(deps.config),
		// `loginCompletion` is the login-completion module's
		// (`modules/loginCompletionModule.mts`): it answers with the
		// deployment's `csrfGuard`, a slot this module fills and so cannot
		// require.
	},
	contributes: {
		// `/session/login`'s budget, `rateLimit.login`, for every limiter to
		// read; an operator's `limits.login` on the limiter still wins.
		rateLimitBudgets: {
			[LOGIN_RATE_LIMIT_PREFIX]: (deps) => readLoginRateLimitBudget(deps.config),
		},
		routes: [
			(deps) => {
				const config = deps.config as AppConfig;
				return {
					id: "session-routes",
					mountPath: "/session",
					handler: sessionRoutes.createRouter(express, {
						userRepository: deps.userRepository,
						config,
						deploymentMode: deps.deploymentMode,
						userSessionStore: deps.userSessionStore,
						// `POST /session/logout` invalidates the records the session
						// owns, not just the cookie. Both stores are already in this
						// module's `requires` for the federation routes, so handing
						// them to the session routes adds no manifest surface.
						federationTokenStore: deps.federationTokenStore,
						sessionFederationIndex: deps.sessionFederationIndex,
						// The CSRF token's signer, the one `csrfGuard` signs with.
						csrfTokenSigner: deps.csrfTokenSigner,
						...(deps.rateLimiter ? { rateLimiter: deps.rateLimiter } : {}),
						...(deps.auditSink ? { auditSink: deps.auditSink } : {}),
						...(deps.subjectSessionIndex ? { subjectSessionIndex: deps.subjectSessionIndex } : {}),
						sessionTtlMs: config.session.maxAge,
						logger: deps.logger ?? consoleLogger,
						// A password login asks the registered requirements through
						// admitPrimary before anything is written; read per request.
						requirements: deps.sessionRequirementResolver,
					}),
				};
			},
			(deps) => {
				const config = deps.config as AppConfig;
				return {
					id: "federation-routes",
					mountPath: "/session",
					handler: federationRoutes.createRouter(express, {
						config,
						federationProviders: deps.federationProviders,
						federationRedirectPolicyResolver: deps.federationRedirectPolicyResolver,
						providerCallbackUrls: deriveProviderCallbackUrls(config.federations),
						userRepository: deps.userRepository,
						userSessionStore: deps.userSessionStore,
						sessionFederationIndex: deps.sessionFederationIndex,
						...(deps.subjectSessionIndex ? { subjectSessionIndex: deps.subjectSessionIndex } : {}),
						// The link flow admits its session with these: the resolver,
						// read per request, and the boundary when it is wired.
						requirements: deps.sessionRequirementResolver,
						...(deps.subjectRevocation ? { subjectRevocation: deps.subjectRevocation } : {}),
						federationTokenStore: deps.federationTokenStore,
						sessionTtlMs: config.session.maxAge,
						// Named after the deployment's session cookie, as the CSRF
						// cookie is, so an operator reading `Set-Cookie` can tell whose.
						federationTransactionCookieName: deriveFederationTransactionCookieName(
							config.session.name,
						),
						...(deps.auditSink ? { auditSink: deps.auditSink } : {}),
						logger: deps.logger ?? consoleLogger,
					}),
				};
			},
		],
	},
});
