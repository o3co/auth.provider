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
 * The module that builds core's subject revocation service.
 *
 * It lives here, not in core, because tearing one session down is
 * `cascadeLogout`, an ordered four-store sequence this package owns, and core
 * cannot import it without inverting the package dependency.
 *
 * Installed explicitly, not folded into `oauthModule`: those routes work in a
 * deployment with no session stores at all, and requiring the whole cascade
 * from the module that serves `/oauth/token` would break such deployments.
 *
 * It reads no configuration: the lifetimes come from the `oauthTokenSettings`
 * and `sessionCookiePolicy` slots, and whether grants are on and may be kept
 * from the `federationGrantPolicy` slot.
 */

import {
	type AuditEvent,
	type AuditSink,
	auditErrorText,
	checkFederationGrantPolicy,
	checkOAuthTokenSettings,
	createSubjectRevocationService,
	defineModule,
	type FederationGrantAuditEvent,
	type FederationGrantPolicy,
	type Logger,
	loggableError,
	type ProviderDeps,
	recordAuditEvent,
	requireFederationGrantSubjectRevocation,
	resolveSubjectRevocationHorizonMs,
} from "@o3co/auth-provider-core";
import { cascadeLogoutUnmarked } from "./cascadeLogout.mjs";

const NAME = "subjectRevocationServiceModule";

const REQUIRES = [
	// The four-store cascade, plus the two stores `cascadeLogout` fans out to.
	"userSessionStore",
	"sessionRPRegistry",
	"sessionFamilyIndex",
	"sessionFederationIndex",
	"refreshTokenFamilyRevocation",
	"federationTokenStore",
	// The session's lifetime, which the boundary must outlive: the session
	// store's, and core reads it from no configuration key.
	"sessionCookiePolicy",
	// The token lifetimes the boundary must outlive: the oauth module's, and
	// a composition without that module fills the slot itself.
	"oauthTokenSettings",
] as const;
/**
 * What turns "this subject" into sessions, and what outlives them, are
 * `optional` although the service needs them: a deployment may declare
 * either capability absent, and a module that required them could not be
 * installed there. Absence is reported in `unavailable` instead. The provider
 * below refuses the pairing that matters: no boundary while federation
 * grants are enabled.
 */
const OPTIONAL = [
	"subjectSessionIndex",
	"subjectRevocation",
	"federationGrantStore",
	"auditSink",
	"logger",
	// Whether grants are on and may be kept: the federation-grants module's,
	// provided while it is on. Absent, grants are off — unless a grant store
	// is wired, which the provider refuses rather than read as off.
	"federationGrantPolicy",
] as const;

/**
 * The deps the provider receives: exactly the module's `requires` /
 * `optional`, typed.
 */
type Requires = (typeof REQUIRES)[number];
type Optional = (typeof OPTIONAL)[number];
export type SubjectRevocationServiceModuleDeps = ProviderDeps<Requires, Optional>;

/** Grants off, and nothing to keep: what a composition that holds no `federationGrantPolicy` has. */
const GRANTS_OFF: FederationGrantPolicy = Object.freeze({
	enabled: false,
	allowKeepOnSubjectRevocation: false,
});

/**
 * The federation grants' switch and keep policy, from the slot held to its
 * contract. No slot is grants off, except beside a grant store: that store
 * says grants may exist, and reading them as off would skip it in a
 * subject-wide revocation that reported itself complete. Grants off with a
 * store wired is a value the host states, not one read from an absence.
 */
const grantPolicyOf = (deps: SubjectRevocationServiceModuleDeps): FederationGrantPolicy => {
	if (deps.federationGrantPolicy !== undefined) {
		return checkFederationGrantPolicy(deps.federationGrantPolicy);
	}
	if (deps.federationGrantStore !== undefined) {
		throw new Error(
			`${NAME}: a federationGrantStore component is wired, but the composition holds no ` +
				"federationGrantPolicy, so whether federation grants are on cannot be read. Read as " +
				"off, a subject-wide revocation would end the sessions and the tokens, report itself " +
				"complete, and skip the grants in that store. Install the federation-grants module " +
				"(federationGrantsModule) and switch it on (federation-grants.enabled = true), which " +
				"provides federationGrantPolicy; or, to keep grants off with the store wired, put " +
				"federationGrantPolicy { enabled: false, allowKeepOnSubjectRevocation: false } in " +
				"bootstrapComponents.",
		);
	}
	return GRANTS_OFF;
};

/**
 * What ended a grant, told to the deployment's sink.
 *
 * No `ip` and no `userAgent`: this is a library call a Store makes after
 * writing a credential, with no request behind it. Inventing one would put
 * the provider's own address in the field an operator reads as "where it
 * came from".
 *
 * Dispatched and not awaited, unlike the route bridge: the caller is a Store
 * in the middle of a credential change it cannot undo, and nothing bounds the
 * wait, so a sink that never settles would hang that call for ever after the
 * grants were revoked. A failure is logged, and the revocation reports what
 * it did.
 */
const auditor = (
	sink: AuditSink,
	logger: Logger | undefined,
): ((event: FederationGrantAuditEvent) => void) => {
	return (event) => {
		const mapped: AuditEvent = {
			timestamp: new Date(),
			type: event.type,
			// Sanitised and capped, as the federation-grants bridge does: both
			// came from a request once, and the sink writes them onto a line.
			subject: auditErrorText(event.subject),
			clientId: event.clientId,
			details: {
				correlationId: event.correlationId,
				grantId: auditErrorText(event.grantId),
				// What access ended, where core established it. Copies,
				// so a sink that holds its argument cannot be handed a
				// reference into what core is still working with.
				...(event.connection === undefined ? {} : { connection: event.connection }),
				// Projected, not spread: the established pair and nothing else.
				...(event.upstream === undefined
					? {}
					: { upstream: { issuer: event.upstream.issuer, subject: event.upstream.subject } }),
				...(event.resource === undefined ? {} : { resource: event.resource }),
				...(event.scopes === undefined ? {} : { scopes: [...event.scopes] }),
				outcome: event.outcome,
				operation: "subject-revocation",
			},
		};
		// `Promise.resolve().then` and not a bare call: a sink that throws
		// synchronously must fail the same way as one that rejects, and
		// neither may reach the caller.
		void Promise.resolve()
			.then(() => recordAuditEvent(sink, mapped))
			.catch((err: unknown) => {
				logger?.error(
					{
						err: loggableError(err),
						grantId: auditErrorText(event.grantId),
						correlationId: event.correlationId,
					},
					"federation_grant_audit_failed",
				);
			});
	};
};

/**
 * Wires every store the service needs, and refuses the compositions that would
 * make it lie.
 *
 * The refusals are here rather than at request time because each is structural
 * — what a component *is* — and a subject revocation is the wrong moment to
 * discover that the grants it should have ended had nowhere to be read from.
 * They apply only when grants are enabled, except one: a grant store wired
 * with no `federationGrantPolicy` is refused, since grants could not be read
 * as off without leaving that store's grants standing.
 */
export const subjectRevocationServiceModule = defineModule<Requires, Optional>({
	name: "subject-revocation-service",
	requires: REQUIRES,
	optional: OPTIONAL,
	/**
	 * Eager, because its consumer is not a module: the Store reads
	 * `handle.components.subjectRevocationService` after `createApp` returns,
	 * and the boot planner otherwise builds a component only when something
	 * in the graph needs it. Without this the component is never built and
	 * the refusals below never run; being eager puts them at boot, where a
	 * composition error belongs.
	 */
	lifecycle: { subjectRevocationService: { eager: true } },
	provides: {
		subjectRevocationService: (deps: SubjectRevocationServiceModuleDeps) => {
			const { enabled, allowKeepOnSubjectRevocation } = grantPolicyOf(deps);
			const store = deps.federationGrantStore;
			if (enabled && store === undefined) {
				throw new Error(
					`${NAME}: federation-grants.enabled = true requires a federationGrantStore ` +
						"component. Without it a subject-wide revocation would end the sessions and " +
						"the tokens, report itself complete, and leave every offline credential the " +
						"subject had standing.",
				);
			}
			const subjectRevocation = enabled
				? requireFederationGrantSubjectRevocation({
						module: NAME,
						subjectRevocation: deps.subjectRevocation,
						federationGrantStore: store,
					})
				: deps.subjectRevocation;

			return createSubjectRevocationService({
				subjectSessionIndex: deps.subjectSessionIndex,
				subjectRevocation,
				// No `expiresAt`: this path reads no session, so the cascade lists
				// the families and writes no ended mark. Without a
				// `subjectRevocation` boundary, a code exchanged at the same moment
				// can leave its family unrevoked; with one, the subject watermark
				// covers it.
				cascadeSession: async (sid: string) => ({
					// The cascade answers with its own union, and its `step`
					// is what makes a failure retryable. What this needs is the
					// one bit the helper's loop branches on; the detail is
					// already in the log the cascade wrote.
					ok:
						(
							await cascadeLogoutUnmarked({
								sid,
								refreshTokenFamilyRevocation: deps.refreshTokenFamilyRevocation,
								federationTokenStore: deps.federationTokenStore,
								userSessionStore: deps.userSessionStore,
								sessionRPRegistry: deps.sessionRPRegistry,
								sessionFamilyIndex: deps.sessionFamilyIndex,
								sessionFederationIndex: deps.sessionFederationIndex,
								...(deps.logger === undefined ? {} : { logger: deps.logger }),
							})
						).outcome === "done",
				}),
				// The boundary must outlive the longest-lived thing it covers,
				// which this module can read and the service cannot: the token
				// lifetimes from `oauthTokenSettings` and the session's from
				// `sessionCookiePolicy`. No configuration: core's helper reads
				// one only when it is handed no token settings.
				watermarkTtlMs: resolveSubjectRevocationHorizonMs(undefined, {
					tokenSettings: checkOAuthTokenSettings(deps.oauthTokenSettings),
					sessionCookie: deps.sessionCookiePolicy,
				}),
				...(enabled && store !== undefined ? { federationGrantStore: store } : {}),
				// False whenever grants are off, which the slot's contract holds:
				// an allowance to keep grants in a deployment that has none is
				// an allowance over nothing, and would make the service refuse
				// an adapter that a grantless deployment has every right to use.
				allowKeep: allowKeepOnSubjectRevocation,
				...(deps.auditSink === undefined
					? {}
					: { federationGrantAudit: auditor(deps.auditSink, deps.logger) }),
				...(deps.logger === undefined ? {} : { logger: deps.logger }),
			});
		},
	},
});
