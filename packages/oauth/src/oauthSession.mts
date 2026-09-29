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
	defineModule,
	type Module,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import { createSessionGrant } from "./grants/session.mjs";

/**
 * Returns true if `value` is an explicit opt-in to enable a feature: the
 * boolean `true` (an `application.conf` literal) or the string `"true"`
 * (from `OAUTH_GRANTS_SESSION_ENABLED=true`, since HOCON's `passthrough`
 * sub-trees do not coerce env-var substitutions). Everything else is
 * refused. Mirrors the helper in `oauthAuthorization.mts`.
 */
function isExplicitlyEnabled(value: unknown): boolean {
	return value === true || value === "true";
}

/**
 * Declarative manifest for the session grant. It needs no
 * `clientRepository`: the grant authorizes against `ctx.authenticatedClient`.
 *
 * Secure-default opt-in, as in `oauthAuthorizationModule`: the grant
 * registers only when `config.oauth.grants.session.enabled` is boolean
 * `true` or the string `"true"`; otherwise the factory returns a no-op
 * module with no `contributes` map.
 */
export const oauthSessionModule = (params: { config: AppConfig }): Module => {
	// `oauth.grants` is `z.object({}).passthrough()` in the schema — values
	// arrive unvalidated. The `enabled` field can be the boolean `true` /
	// `false` (HOCON literal) OR the string `"true"` / `"false"` (HOCON env
	// substitution outcome). Typing `enabled` as `unknown` keeps the local
	// cast honest with runtime reality; `isExplicitlyEnabled` performs the
	// strict opt-in narrowing.
	const grantConfig = (params.config.oauth.grants as Record<string, { enabled?: unknown }>).session;
	if (!isExplicitlyEnabled(grantConfig?.enabled)) {
		return defineModule({ name: "oauth-session" });
	}
	// No `configSchema`: this module reads only slices `CoreConfigSchema`
	// declares (`oauth.grants.session.enabled`, `oauth.accessToken`), which
	// boot's composed parse already validates. One is needed only for a read
	// of a key in `fullSectionsSchema` (e.g. `config.session`).
	return defineModule({
		name: "oauth-session",
		// `config` is required because createSessionGrant reads the access-token lifetime from it
		// when building the token response for authenticated sessions.
		// `sessionRequirementResolver`: the synthetic key every consumer of
		// admission takes (ADR 2026-09-28-session-admission); the grant reads
		// the browser session through `admitSession` with it.
		requires: ["config", "keyStore", "sessionRequirementResolver"],
		// The slots admission reads beside the resolver: the durable session,
		// the subject-revocation boundary (applied here when wired), the audit
		// sink for a subject mismatch, and the logger, which carries
		// admission's outage line (`session_admission_unavailable`). Boot hands
		// a module only the slots its manifest names, so without them the
		// grant would read no boundary and log nothing.
		optional: ["userSessionStore", "subjectRevocation", "auditSink", "logger"],
		// Optional to wire, not optional to decide: an unfilled
		// slot must be declared absent, as every other consumer of the two
		// slots declares it, so that the grants installed without `oauthModule`
		// still refuse a composition that left the decision unmade.
		absencePolicies: {
			subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
		},
		contributes: {
			grants: {
				session: (deps) => createSessionGrant(deps),
			},
		},
	});
};
