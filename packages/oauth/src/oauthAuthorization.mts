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
 * The module of the authorization_code, refresh_token, client_credentials and
 * jwt-bearer grants: each switched on, it contributes that grant, and the
 * actions the two session-bound grants admit
 * (`AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS`,
 * `REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS`).
 *
 * One module, built from nothing, switched by its own section: each grant's
 * switch, `oauth-authorization.grants.<grant>.enabled`, is read from
 * `oauth-authorization {}` as boot parsed it, and an absent section or key is
 * off. A grant switched off answers `null` from its factory and registers
 * nothing; with every grant off the module is off (`section.isEnabled`): it
 * registers nothing and requires nothing. The section's defaults live in the
 * package's `config/reference.conf` alone.
 *
 * What the grants need of `oauth {}` — the issuer, the lifetimes, the
 * resource-indicator switch and `requireEmailVerified` — they read from the
 * `oauthTokenSettings` slot, required while the module is on: the oauth
 * module provides it, and a composition without that module fills it. The
 * refresh-token binding rule they read from core's `tokenBindingSettings`
 * slot. The refresh grant still reads `oauth.refreshToken.unknownFamilyPolicy`
 * from `config`, which no slot carries, so the module still requires it.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	type CodeRepository,
	coerceBooleanFromEnv,
	consoleLogger,
	defineModule,
	type ProviderDeps,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	supportsSessionEnd,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import {
	AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS,
	REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS,
} from "./admissionActions.mjs";
import { createAuthorizationGrant } from "./grants/authorization.mjs";
import { createClientCredentialsGrant } from "./grants/clientCredentials.mjs";
import { createJwtBearerGrant, JWT_BEARER_GRANT_TYPE } from "./grants/jwtBearer.mjs";
import { createRefreshTokenGrant } from "./grants/refreshToken.mjs";

/** One grant's own keys: whether it registers, on only when true; absent is off. */
const grantSwitch = z.object({ enabled: coerceBooleanFromEnv.optional() }).strict().optional();

/**
 * The schema of `oauth-authorization {}`, the module's own section, strict at
 * every level: the switch of each grant the module installs, under `grants`.
 * It fills no default: the package's `reference.conf` ships every switch off.
 * Absent, the section is `undefined`, which reads as every grant off.
 */
export const oauthAuthorizationConfigSchema = z
	.object({
		grants: z
			.object({
				authorizationCode: grantSwitch,
				refreshToken: grantSwitch,
				clientCredentials: grantSwitch,
				jwtBearer: grantSwitch,
			})
			.strict()
			.optional(),
	})
	.strict()
	.optional();

/** The module's section as its schema leaves it. */
type OAuthAuthorizationSection = z.output<typeof oauthAuthorizationConfigSchema>;

/** The grants' keys under `grants`, each by the grant it switches. */
type GrantKey = "authorizationCode" | "refreshToken" | "clientCredentials" | "jwtBearer";

/** Each grant's key under `grants`, in the order the section declares them. */
const GRANT_KEYS: readonly GrantKey[] = [
	"authorizationCode",
	"refreshToken",
	"clientCredentials",
	"jwtBearer",
];

/** Whether the grant under `key` is switched on: only when its `enabled` is true. */
const switchedOn = (section: OAuthAuthorizationSection, key: GrantKey): boolean =>
	section?.grants?.[key]?.enabled === true;

/**
 * The module's section, with the paths it moved from and the variables
 * renamed with them: each `oauth.grants.<grant>` refuses boot naming its key
 * under `oauth-authorization.grants`, and its variable is held to the new
 * name. The authorization_code grant's `pkce` block is removed: PKCE with
 * `S256` is mandatory for every authorization-code client, so a key or
 * variable still setting one refuses boot. Parsed whether or not a grant is
 * on, so a setting still written at an old path refuses boot rather than
 * reading as off.
 */
const SECTION = {
	schema: oauthAuthorizationConfigSchema,
	reference: new URL("../config/reference.conf", import.meta.url),
	relocatedFrom: {
		"oauth.grants.authorization_code": "grants.authorizationCode",
		"oauth.grants.authorization_code.pkce": null,
		"oauth.grants.refresh_token": "grants.refreshToken",
		"oauth.grants.client_credentials": "grants.clientCredentials",
		[`oauth.grants.${JWT_BEARER_GRANT_TYPE}`]: "grants.jwtBearer",
	},
	renamedVariables: {
		OAUTH_GRANTS_AUTHORIZATION_CODE_ENABLED: "oauth.grants.authorization_code.enabled",
		OAUTH_GRANTS_AUTHORIZATION_CODE_PKCE_REQUIRE_S256:
			"oauth.grants.authorization_code.pkce.requireS256",
		OAUTH_GRANTS_REFRESH_TOKEN_ENABLED: "oauth.grants.refresh_token.enabled",
		OAUTH_GRANTS_CLIENT_CREDENTIALS_ENABLED: "oauth.grants.client_credentials.enabled",
		OAUTH_GRANTS_JWT_BEARER_ENABLED: `oauth.grants.${JWT_BEARER_GRANT_TYPE}.enabled`,
	},
	// The module's switch: on while any grant is on.
	isEnabled: (section: OAuthAuthorizationSection) =>
		GRANT_KEYS.some((key) => switchedOn(section, key)),
} as const;

const REQUIRES = [
	// The refresh grant reads `oauth.refreshToken.unknownFamilyPolicy` from it,
	// which no slot carries; nothing else here reads it.
	"config",
	"clientRepository",
	"keyStore",
	// The synthetic key every consumer of admission takes (ADR
	// 2026-09-28-session-admission). The authorization_code grant reads the
	// code's session through `admitSession` with it, twice; the refresh grant
	// reads the token's.
	"sessionRequirementResolver",
	// What the oauth module provides of `oauth {}`: the issuer, the lifetimes,
	// the resource-indicator switch and `requireEmailVerified`, which every
	// grant here reads. A composition without that module fills it.
	"oauthTokenSettings",
	// Core's token-binding settings, which boot always fills: the
	// authorization_code and refresh grants read the refresh-token binding
	// rule from it.
	"tokenBindingSettings",
] as const;
const OPTIONAL = [
	// Where the authorization_code grant redeems the codes `/authorize` issues.
	// Optional to wire, not to decide: with the grant on, its factory below
	// refuses to boot without one (`requireCodeRepository`).
	"codeRepository",
	// The audit sink admission emits `session.admission.subject_mismatch`
	// through, when wired.
	"auditSink",
	// Both grant factories (createAuthorizationGrant / createRefreshTokenGrant)
	// read these to back refresh-token rotation persistence and grant
	// policy enforcement. Boot planner only injects keys listed here, so
	// omitting them silently drops both features at the grant boundary.
	"refreshTokenFamilyRotation",
	// The refresh grant must call `revokeFamily` on a rotation `replayed`
	// outcome (RFC 6819 §5.2.2), and the authorization_code grant calls it on
	// the family of an exchange it refuses because a logout ended the session.
	// Both family slots are optional to wire — a composition without the
	// refresh_token grant needs neither — but not optional to decide: with
	// that grant on, its factory below refuses to boot unless both are filled
	// (`requireRefreshTokenFamilies`).
	"refreshTokenFamilyRevocation",
	// The subject watermark, consulted at RT redemption as the backstop
	// for a partial credential-change cascade. With the authorization_code
	// grant on, wiring it requires `userSessionStore`
	// (`requireSessionStoreWithSubjectRevocation`).
	"subjectRevocation",
	// Read by the jwt-bearer grant. Optional so a deployment that
	// never enables that grant is not made to wire one; the grant
	// factory refuses at composition when it is enabled without one.
	"assertionVerifier",
	"userRepository",
	"grantPolicy",
	"userSessionStore",
	"sessionRPRegistry",
	"sessionFamilyIndex",
	"sessionFederationIndex",
	// Core's session lifecycle: where installed, the authorization_code grant
	// joins the session through it instead of the per-session stores.
	"sessionLifecycle",
	// The session lifecycle's record, which admission reads for the
	// authorization_code and refresh_token grants: a closing session is not live.
	"sessionLifecycleStore",
	"logger", // structured logger; security audit logs
] as const;

/** The two slots the refresh_token grant keeps its token families in. */
const REFRESH_TOKEN_FAMILY_SLOTS = [
	"refreshTokenFamilyRotation",
	"refreshTokenFamilyRevocation",
] as const;

/**
 * Refuse the refresh_token grant a composition that has not wired both
 * token-family slots.
 *
 * The grant rotates each refresh token through its family, refuses a
 * replayed one and revokes the family (RFC 9700 §4.14.2, RFC 6819 §5.2.2.3),
 * and `/oauth/revoke` revokes the family the grant reads. Without rotation a
 * refresh token would be redeemed with no rotation and no replay check;
 * without revocation a detected replay would be a 503 and a revoked family
 * never read. A deployment that does not want token families turns the
 * grant off (`oauth-authorization.grants.refreshToken.enabled = false`).
 */
function requireRefreshTokenFamilies(deps: OAuthAuthorizationModuleDeps): void {
	const missing = REFRESH_TOKEN_FAMILY_SLOTS.filter((slot) => deps[slot] === undefined);
	if (missing.length === 0) return;
	throw new Error(
		"The refresh_token grant is enabled (oauth-authorization.grants.refreshToken.enabled) but " +
			`${missing.join(" and ")} ${missing.length === 1 ? "is" : "are"} not wired. The grant ` +
			"rotates each refresh token through its family and revokes the family on a replay, " +
			"and /oauth/revoke revokes the family the grant reads; without them a refresh token " +
			"cannot be rotated, detected as replayed or revoked. Wire a refresh-token family " +
			"store (memoryRefreshTokenFamilyStoreModule for a single replica, or " +
			"redisRefreshTokenFamilyStoreModule) with core's defaultRefreshTokenFamilyRotationModule " +
			"and defaultRefreshTokenFamilyRevocationModule, or turn the grant off.",
	);
}

/**
 * The code repository the authorization_code grant redeems codes from, or a
 * refusal at boot naming the switch. No other grant reads one, so a
 * composition with the grant off wires none.
 */
function requireCodeRepository(deps: OAuthAuthorizationModuleDeps): CodeRepository {
	if (deps.codeRepository !== undefined) return deps.codeRepository;
	throw new Error(
		"The authorization_code grant is enabled (oauth-authorization.grants.authorizationCode.enabled) but " +
			"codeRepository is not wired. The grant redeems the codes /authorize issues into it. " +
			"Wire a code repository (redisCodeRepositoryModule for more than one replica), or turn " +
			"the grant off.",
	);
}

/**
 * Refuse the authorization_code grant a composition that wires
 * `subjectRevocation` without a `userSessionStore`: the grant binds what it
 * issues to the code's session, and subject revocation reaches those tokens
 * through it.
 */
function requireSessionStoreWithSubjectRevocation(deps: OAuthAuthorizationModuleDeps): void {
	if (deps.subjectRevocation === undefined || deps.userSessionStore !== undefined) return;
	throw new Error(
		"The authorization_code grant is enabled (oauth-authorization.grants.authorizationCode.enabled) " +
			"and subjectRevocation is wired, but userSessionStore is not wired. The grant binds the " +
			"tokens it issues to the code's session, and subject revocation reaches them through it. " +
			"Wire a userSessionStore (core's memorySessionStoresModule for a single replica, or " +
			"redisSessionStoresModule), or remove subjectRevocation.",
	);
}

/**
 * Say once, at boot, that the authorization_code grant links families to
 * sessions through an index without the session-end capability: a logout
 * racing a code exchange can then miss the family the exchange opens.
 */
function warnWithoutSessionEnd(deps: OAuthAuthorizationModuleDeps): void {
	const index = deps.sessionFamilyIndex;
	if (deps.userSessionStore === undefined || index === undefined || supportsSessionEnd(index)) {
		return;
	}
	(deps.logger ?? consoleLogger).warn(
		{ slot: "sessionFamilyIndex", kind: index.kind },
		"session_family_index_without_session_end",
	);
}

/**
 * Say once, at boot, that a code exchange the authorization_code grant
 * refuses because a logout ended its session leaves its family record
 * active: the rotation registers it, and no revocation is wired to revoke
 * it. No token of that family was served.
 */
function warnRotationWithoutRevocation(deps: OAuthAuthorizationModuleDeps): void {
	if (
		deps.userSessionStore === undefined ||
		!supportsSessionEnd(deps.sessionFamilyIndex) ||
		deps.refreshTokenFamilyRotation === undefined ||
		deps.refreshTokenFamilyRevocation !== undefined
	) {
		return;
	}
	(deps.logger ?? consoleLogger).warn(
		{ slot: "refreshTokenFamilyRevocation", grant: "authorization_code" },
		"refresh_token_family_rotation_without_revocation",
	);
}

/**
 * The deps every contribution of {@link oauthAuthorizationGrantsModule}
 * receives, besides its section: exactly its `requires` / `optional`, typed.
 * Each grant factory declares the subset it reads, so the wiring below is
 * checked, not trusted.
 */
type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
export type OAuthAuthorizationModuleDeps = ProviderDeps<Requires, Optional>;

/**
 * The authorization_code, refresh_token, client_credentials and jwt-bearer
 * grants — see the file header for what each switch decides. The boot
 * planner registers each `contributes.grants` entry that does not answer
 * `null`; the repositories come through `requires` from the DI graph. List it
 * as it is.
 */
export const oauthAuthorizationGrantsModule = defineModule<
	Requires,
	Optional,
	typeof oauthAuthorizationConfigSchema
>({
	name: "oauth-authorization",
	section: SECTION,
	requires: REQUIRES,
	optional: OPTIONAL,
	// `subjectRevocation` is optional to wire, not optional to decide.
	// This module reads the slot on its own, so a composition that mounts
	// it without `oauthEndpointsModule` (the grants alone, no routes) would
	// otherwise boot with the watermark unfilled and undeclared.
	absencePolicies: {
		subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
		// The same rule for the audit sink admission emits through,
		// declared here as `oauthEndpointsModule` declares it, for the same reason.
		auditSink: AUDIT_SINK_ABSENCE_POLICY,
	},
	contributes: {
		// The actions the two session-bound grants admit, declared whenever the
		// module is on: a declaration registers no grant.
		admissionActions: {
			...AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS,
			...REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS,
		},
		// Each factory takes `Pick<GrantDependencies, …>` of the slots it reads,
		// and this module's typed deps satisfy every pick — so a grant reading a
		// slot this module never declared is a compile error at its wiring below.
		// Secure-default opt-in: a grant whose switch is off answers `null`. The
		// package's reference.conf ships each off; a deployment's own layer, or
		// the switch's variable, turns one on.
		grants: {
			authorization_code: (deps) => {
				if (!switchedOn(deps.section, "authorizationCode")) return null;
				requireSessionStoreWithSubjectRevocation(deps);
				const grant = createAuthorizationGrant({
					...deps,
					codeRepository: requireCodeRepository(deps),
				});
				warnWithoutSessionEnd(deps);
				warnRotationWithoutRevocation(deps);
				return grant;
			},
			refresh_token: (deps) => {
				if (!switchedOn(deps.section, "refreshToken")) return null;
				// Refused at boot, not at the first refresh: see the function.
				requireRefreshTokenFamilies(deps);
				return createRefreshTokenGrant(deps);
			},
			// RFC 7523 jwt-bearer. Opt-in like every other grant, and additionally
			// inert without an `assertionVerifier` — the module lists it optional so
			// a deployment that never enables this grant is not made to wire one,
			// and the factory refuses to register the grant when it is missing
			// rather than registering one that would accept anything.
			[JWT_BEARER_GRANT_TYPE]: (deps) => {
				if (!switchedOn(deps.section, "jwtBearer")) return null;
				const { userRepository, assertionVerifier } = deps;
				if (!userRepository) {
					throw new Error(
						`${JWT_BEARER_GRANT_TYPE} is enabled but no userRepository is wired. ` +
							"The grant resolves the verified handle through " +
							"`authenticateByToken`, so without it there is nothing to resolve " +
							"against and the first request would fail at the call rather than " +
							"at boot.",
					);
				}
				if (!assertionVerifier) {
					throw new Error(
						`${JWT_BEARER_GRANT_TYPE} is enabled but no assertionVerifier is wired. ` +
							"This grant turns a presented assertion into a login, so there is no " +
							"default: the only possible one would accept things. Wire an " +
							"AssertionVerifier (createJwtAssertionVerifier for a signed device JWT, " +
							"or your own for a platform attestation), or disable the grant.",
					);
				}
				// Both are `optional` here and required by the grant; the checks
				// above are what narrow them, so they are handed over by name.
				return createJwtBearerGrant({ ...deps, assertionVerifier, userRepository });
			},
			// client_credentials follows the same opt-in. Per-client
			// `AuthenticatedClient.allowedGrantTypes` (deny-by-absence) is the
			// authoritative access gate; the server-wide switch is a kill switch,
			// and keeps M2M off in deployments that never use it.
			client_credentials: (deps) =>
				switchedOn(deps.section, "clientCredentials") ? createClientCredentialsGrant(deps) : null,
		},
	},
});
