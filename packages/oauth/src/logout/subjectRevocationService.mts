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
 * The module that builds core's subject revocation service (#593, D13).
 *
 * It lives here, and not in core, for the reason `cascadeSession` is a
 * parameter at all: tearing one session down is `cascadeLogout`, a carefully
 * ordered four-store sequence this package owns, and core cannot import it
 * without inverting the package dependency. The orchestration is core's; the
 * wiring is the only part that has to be here.
 *
 * **Installed explicitly.** It is not folded into `oauthModule`, whose routes
 * work perfectly well in a deployment with no session stores at all. Requiring
 * the whole cascade from the module that serves `/oauth/token` would break
 * those deployments to give this one a component it never asked for.
 */

import {
	type AuditEvent,
	type AuditSink,
	createSubjectRevocationService,
	defineModule,
	type FederationGrantAuditEvent,
	fullSectionsSchema,
	type Logger,
	requireFederationGrantSubjectRevocation,
	resolveFederationGrantKeepPolicy,
	resolveSubjectRevocationHorizonMs,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import { cascadeLogout } from "./cascadeLogout.mjs";

const NAME = "subjectRevocationServiceModule";

/**
 * Core strips the keys no installed module declares, and the two this reads —
 * whether grants exist at all, and whether keeping one is allowed — both live
 * in that block. Taking core's shape rather than restating it keeps the
 * `${?VAR}` coercions in one place (#288).
 */
const configSchema = z.object({
	federationGrants: fullSectionsSchema.shape.federationGrants,
});

// biome-ignore lint/suspicious/noExplicitAny: planner-inferred deps shape — the manifest reads only slots it declares in `requires` / `optional`
type AnyDeps = any;

const grantsEnabled = (deps: AnyDeps): boolean =>
	(deps.config as { federationGrants?: { enabled?: boolean } }).federationGrants?.enabled === true;

/**
 * What ended a grant, told to the deployment's sink.
 *
 * No `ip` and no `userAgent`, unlike the route bridge: this is a library call
 * a Store makes after writing a credential, and there is no request behind it
 * to attribute. Inventing one would put the provider's own address in the
 * field an operator reads as "where it came from".
 *
 * **Dispatched and not awaited**, which is the opposite of what the route
 * bridge does, for the opposite reason. There, core bounds its own audit
 * waits and hands the promise to a registry a shutdown drains, so returning
 * it is how a failing sink becomes visible. Here the caller is a Store in the
 * middle of a credential change it cannot undo, and nothing bounds anything:
 * a sink that never settles would hang that call for ever, having already
 * revoked the grants. So the event goes out, a failure is logged, and the
 * revocation reports what it did.
 */
const auditor = (
	sink: AuditSink,
	logger: Logger | undefined,
): ((event: FederationGrantAuditEvent) => void) => {
	return (event) => {
		const mapped: AuditEvent = {
			timestamp: new Date(),
			type: event.type,
			subject: event.subject,
			clientId: event.clientId,
			details: {
				correlationId: event.correlationId,
				grantId: event.grantId,
				// What access ended, where core established it (D18). Copies,
				// so a sink that holds its argument cannot be handed a
				// reference into what core is still working with.
				...(event.connection === undefined ? {} : { connection: event.connection }),
				...(event.upstream === undefined ? {} : { upstream: { ...event.upstream } }),
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
			.then(() => sink.record(mapped))
			.catch((err: unknown) => {
				logger?.error(
					{ err, grantId: event.grantId, correlationId: event.correlationId },
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
 * They apply only when grants are enabled: a deployment with the feature off
 * gets exactly the service #296 would have had.
 */
export const subjectRevocationServiceModule = defineModule({
	name: "subject-revocation-service",
	configSchema,
	requires: [
		"config",
		// The four-store cascade, plus the two stores `cascadeLogout` fans out to.
		"userSessionStore",
		"sessionRPRegistry",
		"sessionFamilyIndex",
		"sessionFederationIndex",
		"refreshTokenFamilyRevocation",
		"federationTokenStore",
	] as const,
	/**
	 * What turns "this subject" into sessions, and what outlives them — both
	 * `optional`, and not because the service can do without them. #406 lets a
	 * deployment declare either capability absent, and a module that REQUIRED
	 * them could not be installed there at all; absence is reported instead,
	 * in `unavailable`, exactly as `revokeAllForSubject` has always reported
	 * it. What is refused is the pairing that matters: no boundary while
	 * federation grants are enabled, below.
	 */
	optional: [
		"subjectSessionIndex",
		"subjectRevocation",
		"federationGrantStore",
		"auditSink",
		"logger",
	] as const,
	/**
	 * Eager, because its consumer is not a module.
	 *
	 * The boot planner builds a component when something in the graph needs
	 * it, and nothing here does: the caller is the Store, which reads
	 * `handle.components.subjectRevocationService` after `createApp` returns.
	 * Without this the module installs, refuses nothing, and provides a
	 * component that is never built — a deployment would find out when the
	 * first password change had nothing to call.
	 *
	 * It also puts the refusals below at boot for every deployment that
	 * installs this module, which is where a composition error belongs.
	 */
	lifecycle: { subjectRevocationService: { eager: true } },
	provides: {
		subjectRevocationService: (deps: AnyDeps) => {
			const enabled = grantsEnabled(deps);
			const store = deps.federationGrantStore;
			if (enabled && store === undefined) {
				throw new Error(
					`${NAME}: federationGrants.enabled = true requires a federationGrantStore ` +
						"component. Without it a subject-wide revocation would end the sessions and " +
						"the tokens, report itself complete, and leave every offline credential the " +
						"subject had standing (D13).",
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
				cascadeSession: async (sid: string) => ({
					// `cascadeLogout` answers with its own union, and its `step`
					// is what makes a failure retryable. What this needs is the
					// one bit the helper's loop branches on; the detail is
					// already in the log the cascade wrote.
					ok:
						(
							await cascadeLogout({
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
				// which is configuration this module can read and the service
				// cannot.
				watermarkTtlMs: resolveSubjectRevocationHorizonMs(deps.config),
				...(enabled && store !== undefined ? { federationGrantStore: store } : {}),
				// Gated on the feature: an allowance to keep grants in a
				// deployment that has none is an allowance over nothing, and
				// letting it through would make the service refuse an adapter
				// that a grantless deployment has every right to use.
				allowKeep: enabled && resolveFederationGrantKeepPolicy(deps.config),
				...(deps.auditSink === undefined
					? {}
					: { federationGrantAudit: auditor(deps.auditSink, deps.logger) }),
				...(deps.logger === undefined ? {} : { logger: deps.logger }),
			});
		},
	} as never,
});
