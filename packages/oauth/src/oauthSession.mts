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
	coerceBooleanFromEnv,
	defineModule,
	type Module,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import { SESSION_GRANT_ADMISSION_ACTIONS } from "./admissionActions.mjs";
import { createSessionGrant } from "./grants/session.mjs";

/** `oauth-session.enabled`: off unless the operator says so. */
const ENABLED = coerceBooleanFromEnv.optional();

/**
 * The schema of `oauth-session {}`, the module's own section, strict: its one
 * key is whether the session grant registers. Absent, the grant is off; the
 * default is the package's `reference.conf`'s.
 */
export const oauthSessionConfigSchema = z.object({ enabled: ENABLED }).strict().optional();

/**
 * The module's section, with the path it moved from and the variable renamed
 * with it: `oauth.grants.session.enabled` refuses boot naming
 * `oauth-session.enabled`, and `OAUTH_GRANTS_SESSION_ENABLED` is held to its
 * new name, `OAUTH_SESSION_ENABLED`. Declared whether or not the grant is on,
 * so a setting still written at the old path refuses boot rather than reading
 * as off.
 */
const SECTION = {
	schema: oauthSessionConfigSchema,
	reference: new URL("../config/reference.conf", import.meta.url),
	relocatedFrom: { "oauth.grants.session": "" },
	renamedVariables: { OAUTH_GRANTS_SESSION_ENABLED: "oauth.grants.session.enabled" },
} as const;

/**
 * Whether the grant is on in the configuration the composition root read
 * before boot: `oauth-session.enabled` read as the section's schema reads it,
 * so an environment variable's `"true"` is on. Anything the schema refuses is
 * off, the secure default, and boot then refuses the value.
 */
const isEnabled = (config: unknown): boolean => {
	const written = (config as { "oauth-session"?: { enabled?: unknown } } | undefined)?.[
		"oauth-session"
	]?.enabled;
	const read = ENABLED.safeParse(written);
	return read.success && read.data === true;
};

/**
 * The module's section, held to the decision the module was built with:
 * whether the grant registers is decided from the configuration handed to
 * `oauthSessionModule`, before boot, and `oauth-session.enabled` is parsed
 * again from the configuration `createApp` is handed. A switch that reads
 * otherwise there refuses boot, naming the key, in either direction; a
 * composition would otherwise run without a grant its configuration turns on,
 * or with one it turns off.
 */
const sectionFor = (enabled: boolean) => ({
	...SECTION,
	schema: oauthSessionConfigSchema.superRefine((section, ctx) => {
		const booted = section?.enabled === true;
		if (booted === enabled) return;
		const [built, parsed] = enabled ? ["on", "off"] : ["off", "on"];
		ctx.addIssue({
			code: "custom",
			path: ["enabled"],
			message:
				`oauthSessionModule was built from a configuration with the session grant ${built}, ` +
				`but the configuration createApp parsed has oauth-session.enabled ${parsed}. ` +
				"Whether the grant registers is decided from the first. Hand oauthSessionModule " +
				"the configuration read from the same files and environment as the one createApp is handed.",
		});
	}),
});

/**
 * Declarative manifest for the session grant. It needs no
 * `clientRepository`: the grant authorizes against `ctx.authenticatedClient`.
 *
 * Secure-default opt-in: the grant registers only when `oauth-session.enabled`
 * is on in the configuration handed here; otherwise the module contributes
 * nothing. Hand it the configuration the composition root boots with.
 */
export const oauthSessionModule = (params: { config: AppConfig }): Module => {
	const enabled = isEnabled(params.config);
	if (!enabled) {
		return defineModule({ name: "oauth-session", section: sectionFor(enabled) });
	}
	return defineModule({
		name: "oauth-session",
		section: sectionFor(enabled),
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
			admissionActions: SESSION_GRANT_ADMISSION_ACTIONS,
			grants: {
				session: (deps) => createSessionGrant(deps),
			},
		},
	});
};
