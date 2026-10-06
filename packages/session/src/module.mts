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
	AUDIT_SINK_ABSENCE_POLICY,
	type CsrfGuard,
	type CsrfTokenSigner,
	consoleLogger,
	defineModule,
	type FederationSettings,
	LOGIN_RETURN_PARAMETER,
	type Logger,
	loginPageCarriesReturn,
	type SessionCookiePolicy,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	verifierLimitClaim,
	wholeNumberInRangeFromEnv,
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
import { deriveFederationTransactionCookieName } from "./federations/transaction.mjs";
import { createLoginEntry } from "./login-entry.mjs";
import { LOGIN_ATTEMPT_TAG, MAX_LOGIN_WINDOW_MS } from "./loginAttempts.mjs";
import * as federationRoutes from "./routes/Federation.mjs";
import * as sessionRoutes from "./routes/Session.mjs";

/**
 * The schema of `session {}`, the module's own section, strict at every
 * level: where `POST /session/login` may send a browser back to, the CSRF
 * policy, the login page and the login's attempt limit. The session
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
				ttlSeconds: wholeNumberInRangeFromEnv(1, MAX_CSRF_TTL_SECONDS),
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
		 * `POST /session/login`'s own attempt limit, `windowMs` in milliseconds
		 * up to a day, counted on the `attemptCounter` slot's counter, never a
		 * rate limiter's: required (the package's reference ships 20 per 15
		 * minutes). Zero would turn the guard into a no-op that still looks
		 * configured.
		 */
		rateLimit: z
			.object({
				login: z
					.object({
						windowMs: wholeNumberInRangeFromEnv(1, MAX_LOGIN_WINDOW_MS),
						limit: wholeNumberInRangeFromEnv(1),
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
 * the login's attempt limit from `rateLimit.login`, which no variable binds.
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
 * Each enabled federation's name and `callbackURL`, from core's
 * `federationSettings`. Boot refuses an enabled entry without a non-empty
 * `callbackURL` before any route is built, so every enabled entry carries
 * one; a disabled entry's is not read.
 */
const providerCallbackUrlsOf = (settings: FederationSettings): ReadonlyMap<string, string> =>
	new Map(
		Object.entries(settings).flatMap(([name, entry]) =>
			entry.enabled && entry.callbackURL !== undefined ? [[name, entry.callbackURL] as const] : [],
		),
	);

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
 * Its section is `session {}` (`sessionSectionSchema`); it reads nothing else
 * of the configuration.
 *
 * `requires`: `userRepository`; core's `federationSettings`, the federations
 * `core.federations` declares (each enabled one's callback URL, and whether
 * an installed one's upstream `amr` counts); the two stores these routes
 * use (`userSessionStore`, `federationTokenStore`);
 * `csrfTokenSigner`, what the CSRF token is signed and checked with (the
 * session store's module provides it from `session-store.secret`, which this
 * module never reads); `sessionCookiePolicy`, the session cookie's name,
 * attributes and lifetime (the CSRF cookie's, the session TTL, the federation
 * transaction cookie's name), which the session store's module owns; and the
 * planner-derived `federationProviders`,
 * `federationRedirectPolicyResolver` and `sessionRequirementResolver`
 * (password login and the federation link routes go through admission), and
 * `deploymentMode` (counting login attempts per process is refused under
 * `multi`, so a mode read as absent must not lift that).
 *
 * `provides` what other packages need of the browser session through
 * core-owned slot contracts, so none imports this package: `csrfGuard` and
 * `loginEntry`. `providerCallbackUrls` is derived from `federationSettings`
 * inside the federation-routes lambda.
 */
export const sessionModule = defineModule<
	| "federationSettings"
	| "userRepository"
	| "userSessionStore"
	| "federationTokenStore"
	| "csrfTokenSigner"
	| "sessionCookiePolicy"
	| "federationProviders"
	| "federationRedirectPolicyResolver"
	| "sessionRequirementResolver"
	| "deploymentMode",
	| "logger"
	| "attemptCounter"
	| "auditSink"
	| "subjectSessionIndex"
	| "subjectRevocation"
	| "sessionLifecycleStore"
	| "sessionLifecycle",
	typeof sessionSectionSchema
>({
	name: "session",
	section: SECTION,
	requires: [
		"federationSettings",
		"userRepository",
		"userSessionStore",
		"federationTokenStore",
		"csrfTokenSigner",
		"sessionCookiePolicy",
		"federationProviders",
		"federationRedirectPolicyResolver",
		"sessionRequirementResolver",
		"deploymentMode",
	],
	// All optional so a composition without them still boots: without
	// `attemptCounter` the login's attempts are counted per process where the
	// deployment mode allows it; without `auditSink` no events are emitted; without
	// `subjectSessionIndex`, `revokeAllForSubject` reports the capability as
	// unavailable; `subjectRevocation` is the boundary, and
	// `sessionLifecycleStore` the lifecycle port, the link routes' admission
	// reads when wired. `sessionLifecycle`, core's session lifecycle, opens
	// each login's session record, joins its federations and is what
	// `POST /session/logout` closes the session through: required beside
	// `userSessionStore`, the route factories refuse a composition without it,
	// naming both.
	optional: [
		"logger",
		"attemptCounter",
		"auditSink",
		"subjectSessionIndex",
		"subjectRevocation",
		"sessionLifecycleStore",
		"sessionLifecycle",
	],
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
		// The `login` prefix is claimed with no budget: no limiter decides the
		// login's limit, which the attempt guard counts at the declared setting.
		rateLimitBudgets: {
			[LOGIN_ATTEMPT_TAG]: verifierLimitClaim({ setting: "session.rateLimit.login" }),
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
						// The CSRF token's signer, the one `csrfGuard` signs with.
						csrfTokenSigner: deps.csrfTokenSigner,
						...(deps.attemptCounter ? { attemptCounter: deps.attemptCounter } : {}),
						...(deps.auditSink ? { auditSink: deps.auditSink } : {}),
						...(deps.subjectSessionIndex ? { subjectSessionIndex: deps.subjectSessionIndex } : {}),
						...(deps.sessionLifecycle ? { sessionLifecycle: deps.sessionLifecycle } : {}),
						sessionTtlMs: deps.sessionCookiePolicy.maxAgeMs,
						logger: deps.logger ?? consoleLogger,
						// A password login asks the registered requirements through
						// admitPrimary before anything is written; read per request.
						requirements: deps.sessionRequirementResolver,
					}),
				};
			},
			(deps) => {
				return {
					id: "federation-routes",
					mountPath: "/session",
					handler: federationRoutes.createRouter(express, {
						federationSettings: deps.federationSettings,
						// Where an account-link start may be navigated from: the
						// trust list the CSRF guard reads.
						linkTrustedOrigins: deps.section.csrf?.trustedOrigins ?? [],
						federationProviders: deps.federationProviders,
						federationRedirectPolicyResolver: deps.federationRedirectPolicyResolver,
						providerCallbackUrls: providerCallbackUrlsOf(deps.federationSettings),
						userRepository: deps.userRepository,
						userSessionStore: deps.userSessionStore,
						...(deps.subjectSessionIndex ? { subjectSessionIndex: deps.subjectSessionIndex } : {}),
						// The link flow admits its session with these: the resolver,
						// read per request, and the boundary when it is wired.
						requirements: deps.sessionRequirementResolver,
						...(deps.subjectRevocation ? { subjectRevocation: deps.subjectRevocation } : {}),
						sessionLifecycleStore: deps.sessionLifecycleStore,
						sessionLifecycle: deps.sessionLifecycle,
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
