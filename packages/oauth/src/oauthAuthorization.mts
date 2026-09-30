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
	type AdmissionActionDeclaration,
	type AppConfig,
	AUDIT_SINK_ABSENCE_POLICY,
	type CodeRepository,
	defineModule,
	type GrantHandler,
	type Module,
	type ProviderDeps,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import {
	AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS,
	REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS,
} from "./admissionActions.mjs";
import { createAuthorizationGrant } from "./grants/authorization.mjs";
import { createClientCredentialsGrant } from "./grants/clientCredentials.mjs";
import { createJwtBearerGrant, JWT_BEARER_GRANT_TYPE } from "./grants/jwtBearer.mjs";
import { createRefreshTokenGrant } from "./grants/refreshToken.mjs";

/**
 * Returns true if `value` is an explicit opt-in to enable a feature: the
 * boolean `true` (an `application.conf` literal) or the string `"true"`
 * (from `OAUTH_GRANTS_X_ENABLED=true`, since HOCON's `passthrough` sub-trees
 * such as `oauth.grants.*` do not coerce env-var substitutions). Everything
 * else is refused, including `"false"` and truthy strings like `"yes"` /
 * `"1"`.
 */
function isExplicitlyEnabled(value: unknown): boolean {
	return value === true || value === "true";
}

const REQUIRES = [
	"config",
	"clientRepository",
	"keyStore",
	// The synthetic key every consumer of admission takes (ADR
	// 2026-09-28-session-admission). The authorization_code grant reads the
	// code's session through `admitSession` with it, twice; the refresh grant
	// reads the token's.
	"sessionRequirementResolver",
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
	// outcome (RFC 6819 §5.2.2). Both family slots are
	// optional to wire — a composition without the refresh_token grant
	// needs neither — but not optional to decide: with the grant on, its
	// factory below refuses to boot unless both are filled
	// (`requireRefreshTokenFamilies`).
	"refreshTokenFamilyRevocation",
	// The subject watermark, consulted at RT redemption as the backstop
	// for a partial credential-change cascade.
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
 * grant off (`oauth.grants.refresh_token.enabled = false`).
 */
function requireRefreshTokenFamilies(deps: OAuthAuthorizationModuleDeps): void {
	const missing = REFRESH_TOKEN_FAMILY_SLOTS.filter((slot) => deps[slot] === undefined);
	if (missing.length === 0) return;
	throw new Error(
		"The refresh_token grant is enabled (oauth.grants.refresh_token.enabled) but " +
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
		"The authorization_code grant is enabled (oauth.grants.authorization_code.enabled) but " +
			"codeRepository is not wired. The grant redeems the codes /authorize issues into it. " +
			"Wire a code repository (redisCodeRepositoryModule for more than one replica), or turn " +
			"the grant off.",
	);
}

/**
 * The deps every contribution of {@link oauthAuthorizationModule} receives:
 * exactly its `requires` / `optional`, typed. Each grant factory
 * declares the subset it reads, so the wiring below is checked, not trusted.
 */
type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
export type OAuthAuthorizationModuleDeps = ProviderDeps<Requires, Optional>;

/**
 * Declarative manifest for the authorization_code and refresh_token grants
 * (and the jwt-bearer and client_credentials grants). The boot
 * planner registers its `contributes.grants` entries; the repositories come
 * through `requires` from the DI graph.
 */
export const oauthAuthorizationModule = (params: { config: AppConfig }): Module => {
	// `oauth.grants` is `z.object({}).passthrough()` in the schema — values
	// arrive unvalidated. The `enabled` field can be the boolean `true` /
	// `false` (HOCON literal) OR the string `"true"` / `"false"` (HOCON env
	// substitution outcome). Typing `enabled` as `unknown` keeps the local
	// cast honest with runtime reality; `isExplicitlyEnabled` below performs
	// the strict opt-in narrowing.
	const grantsCfg = params.config.oauth.grants as Record<string, { enabled?: unknown }>;

	// Each factory takes `Pick<GrantDependencies, …>` of the slots it reads,
	// and this module's typed deps satisfy every pick — so a grant reading a
	// slot this module never declared is a compile error at its wiring below.
	const grants: Record<string, (deps: OAuthAuthorizationModuleDeps) => GrantHandler> = {};
	// Each grant that admits a session registers its action beside it.
	const admissionActions: Record<string, AdmissionActionDeclaration> = {};
	// Per the secure-default opt-in discipline: a grant is registered only
	// when `enabled` is explicitly truthy (boolean `true` or the string `"true"`
	// from HOCON env-var substitution — see `isExplicitlyEnabled` above).
	// Library reference.conf sets `enabled = false` as the secure baseline;
	// each deployment's application.conf (or env override) must explicitly
	// flip individual grants to activate them.
	if (isExplicitlyEnabled(grantsCfg.authorization_code?.enabled)) {
		grants.authorization_code = (deps) =>
			createAuthorizationGrant({ ...deps, codeRepository: requireCodeRepository(deps) });
		Object.assign(admissionActions, AUTHORIZATION_CODE_GRANT_ADMISSION_ACTIONS);
	}
	if (isExplicitlyEnabled(grantsCfg.refresh_token?.enabled)) {
		Object.assign(admissionActions, REFRESH_TOKEN_GRANT_ADMISSION_ACTIONS);
		grants.refresh_token = (deps) => {
			// Refused at boot, not at the first refresh: see the function.
			requireRefreshTokenFamilies(deps);
			return createRefreshTokenGrant(deps);
		};
	}
	// RFC 7523 jwt-bearer. Opt-in like every other grant, and additionally
	// inert without an `assertionVerifier` — the module lists it optional so a
	// deployment that never enables this grant is not made to wire one, and the
	// factory below refuses to register the grant when it is missing rather
	// than registering one that would accept anything.
	if (isExplicitlyEnabled(grantsCfg["urn:ietf:params:oauth:grant-type:jwt-bearer"]?.enabled)) {
		grants[JWT_BEARER_GRANT_TYPE] = (deps) => {
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
		};
	}
	// client_credentials follows the same opt-in. Per-client
	// `AuthenticatedClient.allowedGrantTypes` (deny-by-absence) is the
	// authoritative access gate; the server-wide flag is a kill switch, and
	// keeps M2M off in deployments that never use it.
	if (isExplicitlyEnabled(grantsCfg.client_credentials?.enabled)) {
		grants.client_credentials = (deps) => createClientCredentialsGrant(deps);
	}

	// No `configSchema`: this module reads only slices `CoreConfigSchema`
	// declares (`oauth.grants.{authorization_code,refresh_token}.enabled`,
	// `oauth.accessToken`, `oauth.refreshToken.expiresIn`), which boot's
	// composed parse already validates. One is needed only for a read of a
	// key in `fullSectionsSchema` (e.g. `config.session`, `config.endpoints`).
	return defineModule<Requires, Optional>({
		name: "oauth-authorization",
		requires: REQUIRES,
		optional: OPTIONAL,
		// `subjectRevocation` is optional to wire, not optional to decide.
		// This module reads the slot on its own, so a composition that mounts
		// it without `oauthModule` (the grants alone, no routes) would
		// otherwise boot with the watermark unfilled and undeclared.
		absencePolicies: {
			subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
			// The same rule for the audit sink admission emits through,
			// declared here as `oauthModule` declares it, for the same reason.
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
		},
		contributes: { grants, admissionActions },
	});
};
