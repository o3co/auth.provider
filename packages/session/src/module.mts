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
	LOGIN_RETURN_PARAMETER,
	type Logger,
	loginPageCarriesReturn,
	MAX_DURATION_MS,
	type SessionCookiePolicy,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import express from "express";
import { z } from "zod";
import { SESSION_ADMISSION_ACTIONS } from "./admissionActions.mjs";
import {
	createCsrfProtectionFromConfig,
	createSessionCsrfGuard,
	MAX_CSRF_TTL_SECONDS,
	sessionCsrfSlice,
} from "./csrf.mjs";
import { extractFederationSection } from "./federations/extract-federation-section.mjs";
import { deriveFederationTransactionCookieName } from "./federations/transaction.mjs";
import { createLoginEntry } from "./login-entry.mjs";
import { LOGIN_RATE_LIMIT_PREFIX, readLoginRateLimitBudget } from "./loginBudget.mjs";
import * as federationRoutes from "./routes/Federation.mjs";
import * as sessionRoutes from "./routes/Session.mjs";

const sessionConfigSchema = fullSectionsSchema.pick({
	federations: true,
	cors: true,
});

/**
 * The schema of `session {}`, the module's own section, strict at every
 * level: where `POST /session/login` may send a browser back to, the CSRF
 * policy, the login page and the login's rate-limit budget. The session
 * cookie and its store are the session store's (`session-store {}`), read
 * here through the `sessionCookiePolicy` slot. Each leaf reads the string an
 * environment variable carries.
 */
export const sessionSectionSchema = z
	.object({
		/**
		 * The exact URLs `POST /session/login` may accept as `redirect_to`,
		 * matched after `new URL(x).href` normalization, with no wildcard or
		 * prefix form. Absence fails closed: a missing key refuses the redirect.
		 */
		redirectAllowlist: z.array(z.string()).optional(),
		/**
		 * CSRF policy for the state-changing session routes. `trustedOrigins` is
		 * not `cors.allowedOrigins`: "may this origin read my responses" and
		 * "may it make me change state" are separate questions. The TTL is
		 * stringified into the token as its expiry, so it is a whole number of
		 * seconds from 1 to `MAX_CSRF_TTL_SECONDS`.
		 */
		csrf: z
			.object({
				trustedOrigins: z.array(z.string()),
				ttlSeconds: z.coerce.number().int().positive().max(MAX_CSRF_TTL_SECONDS),
			})
			.strict()
			.optional(),
		/**
		 * The deployment's login page, which the `loginEntry` slot sends a
		 * browser that is not signed in to: required (the package's reference
		 * ships `/login`), non-empty, and with no `redirect_to` of its own, as
		 * the slot adds one naming the request to come back to (core's
		 * `LoginEntry` contract).
		 */
		loginPage: z
			.object({
				url: z
					.string()
					.min(1)
					.refine((url) => !loginPageCarriesReturn(url), {
						message: `session.loginPage.url must not carry a "${LOGIN_RETURN_PARAMETER}" query parameter of its own: the provider adds "${LOGIN_RETURN_PARAMETER}" when it sends a browser to the login page, naming the request to come back to`,
					}),
			})
			.strict(),
		/**
		 * `POST /session/login`'s brute-force budget, `windowMs` in
		 * milliseconds, which the module contributes as the `login` budget
		 * every limiter reads: required (the package's reference ships 20 per
		 * 15 minutes). Zero (an exported-but-empty variable) would turn the
		 * guard into a no-op that still looks configured.
		 */
		rateLimit: z
			.object({
				login: z
					.object({
						windowMs: z.coerce.number().int().positive().max(MAX_DURATION_MS),
						limit: z.coerce.number().int().positive(),
					})
					.strict(),
			})
			.strict(),
	})
	.strict();

/** `session {}` as its schema leaves it. */
type SessionSection = z.output<typeof sessionSectionSchema>;

/**
 * The module's section, with the paths it moved from: the login page from
 * `endpoints.login.url` (its variable renamed `SESSION_LOGIN_PAGE_URL`) and
 * the login's budget from `rateLimit.login`, which no variable binds.
 */
const SECTION = {
	schema: sessionSectionSchema,
	reference: new URL("../config/reference.conf", import.meta.url),
	relocatedFrom: {
		"endpoints.login.url": "loginPage.url",
		"rateLimit.login": { to: "rateLimit.login", environmentVariable: null },
	},
	renamedVariables: { ENDPOINTS_LOGIN_URL: "endpoints.login.url" },
} as const;

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
 * `createCsrfProtectionFromConfig` (cookie `<session cookie name>.csrf`, with
 * the session cookie's attributes, signed through `signer`) plus
 * `session.csrf.trustedOrigins`. The session routes build their own
 * `CsrfProtection` over the same signer, so each accepts the other's tokens:
 * the token is signed, not stored.
 */
const csrfGuardOf = (
	section: SessionSection,
	cookie: SessionCookiePolicy,
	signer: CsrfTokenSigner,
	logger: Logger,
): CsrfGuard =>
	createSessionCsrfGuard({
		csrf: createCsrfProtectionFromConfig(sessionCsrfSlice(cookie, section.csrf), { signer }),
		trustedOrigins: section.csrf?.trustedOrigins ?? [],
		logger,
	});

/**
 * The session and federation route surface, as a pre-built `Module` (pass it
 * to the manifest directly; its dependencies come from sibling modules).
 *
 * Routes, both under `/session`:
 *   - "session-routes"    — GET /session/csrf, POST /session/login,
 *                           POST /session/logout
 *   - "federation-routes" — GET /session/oauth/federation/:name (+ callback)
 *
 * Its section is `session {}` (`sessionSectionSchema`); `config` is read for
 * `federations` and `cors` alone.
 *
 * `requires`: `config` and `userRepository`; the three stores these routes
 * use (`userSessionStore`, `federationTokenStore`, `sessionFederationIndex`);
 * `csrfTokenSigner`, what the CSRF token is signed and checked with (the
 * session store's module provides it from `session-store.secret`, which this
 * module never reads); `sessionCookiePolicy`, the session cookie's name,
 * attributes and lifetime (the CSRF cookie's, the session TTL, the federation
 * transaction cookie's name), which the session store's module owns; and the
 * planner-derived `federationProviders`,
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
	| "sessionCookiePolicy"
	| "federationProviders"
	| "federationRedirectPolicyResolver"
	| "sessionRequirementResolver"
	| "deploymentMode",
	"logger" | "rateLimiter" | "auditSink" | "subjectSessionIndex" | "subjectRevocation",
	typeof sessionSectionSchema
>({
	name: "session",
	section: SECTION,
	configSchema: sessionConfigSchema,
	requires: [
		"config",
		"userRepository",
		"userSessionStore",
		"federationTokenStore",
		"sessionFederationIndex",
		"csrfTokenSigner",
		"sessionCookiePolicy",
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
	// declared (`auditSink` in `core.declaredAbsent`), and absent subject-level
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
			csrfGuardOf(
				deps.section,
				deps.sessionCookiePolicy,
				deps.csrfTokenSigner,
				deps.logger ?? consoleLogger,
			),
		// The login page (`session.loginPage.url`) and the `redirect_to`
		// protocol `/authorize` and the federation-grants connect flow send a
		// browser there by.
		loginEntry: (deps) => createLoginEntry(deps.section.loginPage.url),
		// `loginCompletion` is the login-completion module's
		// (`modules/loginCompletionModule.mts`): it answers with the
		// deployment's `csrfGuard`, a slot this module fills and so cannot
		// require.
	},
	contributes: {
		// What the link flow's start and callback admit.
		admissionActions: SESSION_ADMISSION_ACTIONS,
		// `/session/login`'s budget, `session.rateLimit.login`, for every
		// limiter to read; an operator's `limits.login` on the limiter wins.
		rateLimitBudgets: {
			[LOGIN_RATE_LIMIT_PREFIX]: (deps) => readLoginRateLimitBudget(deps.section),
		},
		routes: [
			(deps) => {
				return {
					id: "session-routes",
					mountPath: "/session",
					handler: sessionRoutes.createRouter(express, {
						userRepository: deps.userRepository,
						section: deps.section,
						sessionCookie: deps.sessionCookiePolicy,
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
						sessionTtlMs: deps.sessionCookiePolicy.maxAgeMs,
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
						sessionTtlMs: deps.sessionCookiePolicy.maxAgeMs,
						// Named after the deployment's session cookie, as the CSRF
						// cookie is, so an operator reading `Set-Cookie` can tell whose.
						federationTransactionCookieName: deriveFederationTransactionCookieName(
							deps.sessionCookiePolicy.name,
						),
						...(deps.auditSink ? { auditSink: deps.auditSink } : {}),
						logger: deps.logger ?? consoleLogger,
					}),
				};
			},
		],
	},
});
