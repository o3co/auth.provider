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
	consoleLogger,
	defineModule,
	fullSectionsSchema,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import express from "express";
import { extractFederationSection } from "./federations/extract-federation-section.mjs";
import type { FederationProvider } from "./federations/types.mjs";
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
 * Boot-time projection of `config.federations` to a `name → callbackURL` map.
 *
 * Per A2-γ §3.4 + §3.5: the v0.4.x sessionModule.init() body derived this Map
 * from the same flat / nested config shape that `extractFederationSection`
 * normalizes. After the const-Module conversion the derivation moves into the
 * federation-routes contribution lambda so the construction is colocated with
 * the consumer.
 *
 * Throws when an enabled federation is missing `callbackURL` — this is the
 * same fail-fast invariant the v0.4.x module enforced. Surfacing the error
 * at boot (not at request time) is intentional: a missing callback URL is a
 * deployment misconfiguration, not a per-request condition.
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
 * Const Module for the session and federation route surface.
 *
 * Per A2-γ §3.4 + Amendment 5 (§1.1.5) + Amendment 6 (§1.1.6).
 *
 * Replaces the v0.4.x `sessionModule(opts: SessionModuleOptions): Module`
 * factory. Caller surface:
 *
 *   import { sessionModule } from "@o3co/auth-provider-session";
 *   // pass directly to the manifest list — `sessionModule` is a
 *   // pre-built `Module` value, not a factory; dependencies
 *   // (`userRepository`, `userSessionStore`, etc.) flow in through
 *   // sibling `defineModule(...)` modules that produce them.
 *
 * Two route contributions, both mounted at `/session` (intentional named-route
 * bundle per Codex Session 06 Q6):
 *   - "session-routes"    — POST /session/login, POST /session/logout
 *   - "federation-routes" — GET  /session/oauth/federation/:name (+ callback)
 *
 * `requires` (Amendment 5):
 *   - "config", "userRepository" — bootstrap / DI
 *   - "userSessionStore", "federationTokenStore", "sessionFederationIndex" —
 *     three sibling stores actually consumed by these routes (NOT the four-store
 *     superset; `sessionRPRegistry` and `sessionFamilyIndex` are oauth-package
 *     concerns per `module.mts:84` / `:248` audit pre-conversion).
 *   - "federationProviders" — synthetic (planner-derived from per-federation
 *     `federations.<name>` contributions).
 *   - "federationRedirectPolicyResolver" — synthetic per A5 §7 (planner-derived
 *     from `federationRedirectPolicies.<name>` contributions).
 *
 * `providerCallbackUrls` is derived from `config.federations` inside the
 * federation-routes lambda — a route-local config projection, not a synthetic
 * key. Per A2-γ §11.5 synthetic keys are reserved for planner projections of
 * contribution kinds; callback URLs are config-driven and have no contribution
 * surface, so route-local derivation is the correct level (verified Codex
 * 2026-05-01).
 *
 * Theme B (one responsibility), Theme D (immutable const shape, no ctx mutation),
 * Theme E (typed deps replace lazy ctx closures + factory option indirection).
 */
export const sessionModule = defineModule<
	| "config"
	| "userRepository"
	| "userSessionStore"
	| "federationTokenStore"
	| "sessionFederationIndex"
	| "federationProviders"
	| "federationRedirectPolicyResolver",
	"logger" | "rateLimiter" | "auditSink" | "subjectSessionIndex"
>({
	name: "session",
	configSchema: sessionConfigSchema,
	requires: [
		"config",
		"userRepository",
		"userSessionStore",
		"federationTokenStore",
		"sessionFederationIndex",
		"federationProviders",
		"federationRedirectPolicyResolver",
	],
	// `rateLimiter` is optional so a composition that installs no limiter module
	// still boots; the session router falls back to a private in-memory limiter
	// and warns that the login guard is per-process (#270).
	// `auditSink` is optional for the same reason the oauth module treats it so:
	// no events are emitted when absent (#325 — the login guard now emits
	// `rate_limit.unavailable` on a limiter outage, like the OAuth endpoints).
	// #296: `subjectSessionIndex` is optional so a composition that has not
	// adopted subject-level revocation still boots; `revokeAllForSubject` then
	// reports the capability as unavailable rather than silently doing nothing.
	optional: ["logger", "rateLimiter", "auditSink", "subjectSessionIndex"],
	// #363: `auditSink` is optional to wire, not optional to decide — an
	// unfilled slot must be declared with audit.sink.type = "none" or boot
	// refuses. Same shared policy as the oauth and webauthn modules.
	// #406: subject-level revocation is optional to wire, not optional to
	// decide. Its absence must be declared with
	// oauth.revocation.subject = "unsupported", or a credential change
	// silently invalidates nothing that was already issued.
	absencePolicies: {
		auditSink: AUDIT_SINK_ABSENCE_POLICY,
		subjectSessionIndex: SUBJECT_REVOCATION_ABSENCE_POLICY,
	},
	contributes: {
		routes: [
			(deps) => {
				const config = deps.config as AppConfig;
				return {
					id: "session-routes",
					mountPath: "/session",
					handler: sessionRoutes.createRouter(express, {
						userRepository: deps.userRepository,
						config,
						userSessionStore: deps.userSessionStore,
						...(deps.rateLimiter ? { rateLimiter: deps.rateLimiter } : {}),
						...(deps.auditSink ? { auditSink: deps.auditSink } : {}),
						...(deps.subjectSessionIndex ? { subjectSessionIndex: deps.subjectSessionIndex } : {}),
						sessionTtlMs: config.session.maxAge,
						logger: deps.logger ?? consoleLogger,
					}),
				};
			},
			(deps) => {
				const config = deps.config as AppConfig;
				// Cast bridges core's placeholder `FederationProvider = unknown`
				// (contributes-map.mts:47) to this package's structural
				// `FederationProvider` interface. Same shape at runtime; the cast
				// is the one-way bridge from the planner's typed-but-erased view
				// to the consumer's structurally-typed view.
				const federationProviders = deps.federationProviders as ReadonlyMap<
					string,
					FederationProvider
				>;
				return {
					id: "federation-routes",
					mountPath: "/session",
					handler: federationRoutes.createRouter(express, {
						config,
						federationProviders,
						federationRedirectPolicyResolver: deps.federationRedirectPolicyResolver,
						providerCallbackUrls: deriveProviderCallbackUrls(config.federations),
						userRepository: deps.userRepository,
						userSessionStore: deps.userSessionStore,
						sessionFederationIndex: deps.sessionFederationIndex,
						...(deps.subjectSessionIndex ? { subjectSessionIndex: deps.subjectSessionIndex } : {}),
						federationTokenStore: deps.federationTokenStore,
						sessionTtlMs: config.session.maxAge,
						logger: deps.logger ?? consoleLogger,
					}),
				};
			},
		],
	},
});
