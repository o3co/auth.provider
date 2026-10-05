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
 * The module of the session grant: enabled, it contributes the `session`
 * grant and the action it admits (`SESSION_GRANT_ADMISSION_ACTIONS`).
 *
 * One module, built from nothing, switched by its own section: the switch,
 * `oauth-session.enabled`, is read from `oauth-session {}` as boot parsed it
 * (`section.isEnabled`), and an absent section or key is off. Off, the
 * module registers nothing and requires nothing. The section's default lives
 * in the package's `config/reference.conf` alone.
 *
 * It reads no whole configuration. What the grant needs of `oauth {}` — the
 * access-token lifetime and `requireEmailVerified` — it reads from the
 * `oauthTokenSettings` slot, required while the grant is on: the oauth
 * module provides it, and a composition without that module fills it.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	coerceBooleanFromEnv,
	defineModule,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import { SESSION_GRANT_ADMISSION_ACTIONS } from "./admissionActions.mjs";
import { createSessionGrant } from "./grants/session.mjs";

/**
 * The schema of `oauth-session {}`, the module's own section, strict: its one
 * key is whether the session grant registers. It fills no default: the
 * package's `reference.conf` ships it. Absent, the section is `undefined`,
 * which the switch reads as off.
 */
export const oauthSessionConfigSchema = z
	.object({
		/** The module's switch: on only when true; absent is off. */
		enabled: coerceBooleanFromEnv.optional(),
	})
	.strict()
	.optional();

const REQUIRES = [
	"keyStore",
	// Session admission's synthetic key: the grant reads the browser session
	// through `admitSession` with it. The planner always fills it.
	"sessionRequirementResolver",
	// What the oauth module provides of `oauth {}`: the access-token lifetime
	// and `requireEmailVerified`. A composition without that module fills it.
	"oauthTokenSettings",
] as const;
// The slots admission reads beside the resolver: the durable session, the
// subject-revocation boundary (applied here when wired), the audit sink for a
// subject mismatch, and the logger, which carries admission's outage line
// (`session_admission_unavailable`). Boot hands a module only the slots its
// manifest names, so without them the grant would read no boundary and log
// nothing. `grantPolicy`: the grant consults it, when wired, before it mints.
const OPTIONAL = [
	"userSessionStore",
	"subjectRevocation",
	"sessionLifecycleStore",
	"auditSink",
	"grantPolicy",
	"logger",
] as const;

/**
 * The module's section, with the path it moved from and the variable renamed
 * with it: `oauth.grants.session.enabled` refuses boot naming
 * `oauth-session.enabled`, and `OAUTH_GRANTS_SESSION_ENABLED` is held to its
 * new name, `OAUTH_SESSION_ENABLED`. Parsed whether or not the grant is on,
 * so a setting still written at the old path refuses boot rather than
 * reading as off.
 */
const SECTION = {
	schema: oauthSessionConfigSchema,
	reference: new URL("../config/reference.conf", import.meta.url),
	relocatedFrom: { "oauth.grants.session": "" },
	renamedVariables: { OAUTH_GRANTS_SESSION_ENABLED: "oauth.grants.session.enabled" },
	// The module's switch: on only when the section says so.
	isEnabled: (section: z.output<typeof oauthSessionConfigSchema>) => section?.enabled === true,
} as const;

/**
 * The session grant — see the file header for what `oauth-session.enabled`
 * decides. It needs no `clientRepository`: the grant authorizes against
 * `ctx.authenticatedClient`. List it as it is.
 */
export const oauthSessionGrantModule = defineModule<
	(typeof REQUIRES)[number],
	(typeof OPTIONAL)[number],
	typeof oauthSessionConfigSchema
>({
	name: "oauth-session",
	section: SECTION,
	requires: REQUIRES,
	optional: OPTIONAL,
	// Optional to wire, not optional to decide: an unfilled slot must be
	// declared absent, as every other consumer of the two slots declares it,
	// so that the grants installed without `oauthModule` still refuse a
	// composition that left the decision unmade.
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

/**
 * Returns {@link oauthSessionGrantModule}; the argument is ignored.
 *
 * @deprecated List {@link oauthSessionGrantModule} instead.
 */
export const oauthSessionModule = (_params?: {
	readonly config?: unknown;
}): typeof oauthSessionGrantModule => oauthSessionGrantModule;
