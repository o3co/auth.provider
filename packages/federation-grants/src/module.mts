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
 * The two manifests this package installs (#593, D9–D12).
 *
 * ### Why a package, and not `/oauth/token`
 *
 * What these routes disclose is an *upstream* access token, held on a user's
 * standing consent, for a backend the user is not present at. Behind
 * `/oauth/token` it would inherit grant dispatch, `token.issued`, this
 * provider's token minting and a sender-constraint policy that cannot bind a
 * credential another issuer minted. Inside the oauth package it would make an
 * optional feature part of every deployment's routing surface, so enabling
 * ordinary OAuth would acquire this lifecycle by accident.
 *
 * ### Why two modules
 *
 * `federationGrantBackgroundModule` provides the registry that a shutdown
 * drains; `federationGrantsModule` mounts the routes and requires it. They are
 * separate because their dependency edges point in different directions: the
 * registry must be built *after* the store, the revocation boundary and the
 * sink so that its cleanup runs *before* theirs, while the routes need nothing
 * of the sort. Install them together —
 *
 *     modules: [...federationGrantsModules, ...]
 *
 * — which is what {@link federationGrantsModules} is for. Mounting the routes
 * without the registry is a boot refusal rather than a shutdown that silently
 * drops rotated credentials.
 *
 * ### Secure-default opt-in
 *
 * `federationGrants.enabled = false` in `reference.conf`. Installing a package
 * must not turn on offline delegation; the operator says so. A disabled
 * deployment answers the same 404 a deployment without the package answers,
 * and reads none of the feature's configuration or components on the way.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	defineModule,
	type FederationGrantConnection,
	type FederationGrantRefresher,
	fullSectionsSchema,
	type RateLimitFailMode,
	requireFederationGrantSubjectRevocation,
	resolveFederationGrantRetrievalLimits,
	type SupportsSessionsOnlyRevocation,
} from "@o3co/auth-provider-core";
import { supportsDelegatedAuthorization } from "@o3co/auth-provider-session";
import { z } from "zod";
import { createFederationGrantBackground } from "./background.mjs";
import { resolveFederationGrantConnections } from "./connections.mjs";
import { createDisabledFederationGrantRouter, createFederationGrantRouter } from "./routes.mjs";
import { FEDERATION_GRANTS_MOUNT_PATH } from "./types.mjs";

/**
 * The slice both routes read — core's own declaration of it, projected.
 *
 * Not a restatement. `AppConfigSchema` is a strip-mode object and the boot
 * planner composes every module's `configSchema` into one parse, so a key this
 * module does not declare is GONE by the time the factory reads it: a narrower
 * copy here would leave the connections and every retrieval limit at their
 * defaults while an operator's file said otherwise, and the boot refusals that
 * exist to catch a bad one would never see it. That is how this was found.
 *
 * Taking core's shape rather than mirroring it also keeps the `${?VAR}`
 * coercions (#288) in one place: HOCON substitutes every environment override
 * as a string, and `enabled` is the one where a leftover string reads as off.
 */
export const federationGrantsConfigSchema = z.object({
	federationGrants: fullSectionsSchema.shape.federationGrants,
});

// biome-ignore lint/suspicious/noExplicitAny: planner-inferred deps shape — the manifest reads only slots it declares in `requires` / `optional`
type AnyDeps = any;

const isEnabled = (deps: AnyDeps): boolean =>
	(deps.config as { federationGrants?: { enabled?: boolean } }).federationGrants?.enabled === true;

/**
 * §5 refusal 1. An enabled deployment with nowhere to keep grants would
 * authenticate a client and then answer 503 to everything, having accepted
 * `enabled = true` as if it meant something.
 */
const requireStore = (deps: AnyDeps): NonNullable<AnyDeps["federationGrantStore"]> => {
	if (deps.federationGrantStore === undefined) {
		throw new Error(
			"federationGrantsModule: federationGrants.enabled = true requires a " +
				"federationGrantStore component. A grant is a user's standing consent that " +
				"outlives their session, so there is nowhere to read one from and nothing to " +
				"write a rotated credential back to without it. Install the bundled memory " +
				"store (single replica only) or an adapter such as " +
				"redisFederationGrantStoreModule.",
		);
	}
	return deps.federationGrantStore;
};

/**
 * §5 refusal 2. Both routes are throttled before client authentication, so
 * that repeated unauthenticated hits are bounded before they reach a
 * repository lookup — and what happens when the limiter backend is down is the
 * product's decision (`rateLimit.failMode`), not this module's to default.
 */
const requireLimiter = (deps: AnyDeps): NonNullable<AnyDeps["rateLimiter"]> => {
	if (deps.rateLimiter === undefined) {
		throw new Error(
			"federationGrantsModule: federationGrants.enabled = true requires a rateLimiter " +
				"component. These routes take an opaque grant id in the path and answer the " +
				"same 404 for an unknown one, for another client's and for another subject's " +
				"— which is only a defence while the number of guesses is bounded.",
		);
	}
	return deps.rateLimiter;
};

const requireFailMode = (deps: AnyDeps): RateLimitFailMode => {
	const failMode = deps.config?.rateLimit?.failMode;
	if (failMode !== "open" && failMode !== "closed") {
		throw new Error(
			'federationGrantsModule: federationGrants.enabled = true requires rateLimit.failMode ("open" | "closed"). ' +
				"It is the product's one policy for a limiter-backend outage, and these routes " +
				"apply it like every other throttled route rather than choosing for themselves.",
		);
	}
	return failMode;
};

/**
 * §5 refusals 5 and 6, together, because they are one question asked of the
 * same map: can this deployment actually refresh a grant on this connection
 * without the user?
 *
 * Resolved in the route contribution phase rather than while components are
 * materialised: named federation contributions are assembled first, and
 * checking the synthetic map earlier would refuse a configuration whose
 * provider simply had not been contributed yet.
 *
 * Refusal 6 is about BOTH delegated methods. An adapter with an ordinary
 * `refreshToken` is not enough: that one refreshes a session's token with the
 * session's own credentials, and says nothing about whether this provider may
 * act for a user who is not here. Slice 2 implemented the pair for the generic
 * OIDC adapter only, so a `form_post` federation such as Apple's is refused
 * here, by this rule, for the true reason — which is why this slice has no
 * separate refusal about response modes.
 */
const requireDelegatedCapability = (
	deps: AnyDeps,
	connections: ReadonlyMap<string, FederationGrantConnection>,
): void => {
	const providers = deps.federationProviders as ReadonlyMap<string, unknown> | undefined;
	for (const connection of connections.values()) {
		const provider = providers?.get(connection.federation);
		if (provider === undefined) {
			throw new Error(
				`federationGrantsModule: federationGrants.connections.${connection.name} names the ` +
					`federation "${connection.federation}", which no installed module contributes. ` +
					"A connection whose provider is absent can never be refreshed, and a grant on " +
					"it would be created and then fail every time it is spent.",
			);
		}
		if (!supportsDelegatedAuthorization(provider as never)) {
			throw new Error(
				`federationGrantsModule: the federation "${connection.federation}", named by ` +
					`federationGrants.connections.${connection.name}, has no delegated ` +
					"authorization capability. Offline delegation needs BOTH " +
					"`buildDelegatedAuthorizationUrl` and `refreshDelegatedToken`: an ordinary " +
					"`refreshToken` renews a token inside a session and says nothing about " +
					"acting for a user who is not present.",
			);
		}
	}
};

/**
 * §5 refusal 9. #363's rule — optional to wire, not optional to decide — for
 * the events an operator needs most: every disclosure of a credential that
 * works while nobody is watching.
 *
 * Checked here rather than through `absencePolicies`, which the boot planner
 * applies to a module whether or not its feature is on. A deployment that
 * installs this package and leaves `enabled = false` must owe nothing, and a
 * configuration declaration is still something to owe. The message is built
 * from the shared policy so it cannot drift from the one every other module
 * gives for the same slot.
 */
const requireAuditDecision = (deps: AnyDeps): void => {
	if (deps.auditSink !== undefined) return;
	const declared = deps.config?.audit?.sink?.type;
	if (declared === AUDIT_SINK_ABSENCE_POLICY.absentValue) return;
	throw new Error(
		"federationGrantsModule: federationGrants.enabled = true with no auditSink component. " +
			`Wire one, or set ${AUDIT_SINK_ABSENCE_POLICY.configKey.join(".")} = ` +
			`"${AUDIT_SINK_ABSENCE_POLICY.absentValue}" to declare the capability absent on purpose. ` +
			AUDIT_SINK_ABSENCE_POLICY.hint,
	);
};

/** The refresher core calls: the connection's provider, or nothing for one that lost its capability. */
const refresherFor =
	(deps: AnyDeps) =>
	(connection: FederationGrantConnection): FederationGrantRefresher | undefined => {
		const providers = deps.federationProviders as ReadonlyMap<string, unknown> | undefined;
		const provider = providers?.get(connection.federation);
		if (!supportsDelegatedAuthorization(provider as never)) return undefined;
		return {
			refreshDelegatedToken: (params) =>
				(
					provider as { refreshDelegatedToken: FederationGrantRefresher["refreshDelegatedToken"] }
				).refreshDelegatedToken(params),
		};
	};

/**
 * The subject's grants boundary (#593, D13).
 *
 * `grantsRevokedBefore`, and deliberately not `revokedBefore`: the two move
 * independently now. A subject-wide revocation that was asked to keep this
 * subject's grants advances the sessions boundary alone, and reading that one
 * here would revoke the grants an operator's policy just chose to keep — the
 * feature would look implemented and do the opposite.
 *
 * The adapter is the one the boot refusal above returned, so this no longer
 * has an absent-capability branch: a deployment without the capability does
 * not get here. What stays is the answer's own validation, because boot cannot
 * establish what a backend will say about a subject that does not exist yet.
 */
const boundaryFor =
	(revocation: SupportsSessionsOnlyRevocation): ((subject: string) => Promise<Date | null>) =>
	async (subject) => {
		const watermark = await revocation.grantsRevokedBefore(subject);
		// The port says `Date | null`, and a `null` is a STATEMENT: nothing was
		// revoked for this subject. An adapter that answers `undefined` — or
		// anything else — has made no statement at all, and reading it as one
		// switches the backstop off for that subject silently. Review found
		// `/status` doing exactly that while `/token` failed closed on the same
		// input, so the two disagreed about the same grant. This is where the
		// contract belongs, and now both read it the same way.
		if (watermark === null) return null;
		if (watermark instanceof Date && !Number.isNaN(watermark.getTime())) return watermark;
		throw new Error(
			"federationGrantsModule: the subjectRevocation adapter answered something that is " +
				"neither a date nor null for the subject's grants boundary. Fails closed: an " +
				"answer that cannot be compared is not the same as no revocation (D13).",
		);
	};

export const federationGrantBackgroundModule = defineModule({
	name: "federation-grant-background",
	/**
	 * Not read — and that is what they are for.
	 *
	 * `dispose()` runs component cleanups in reverse of the order the
	 * components were built in, so the registry's drain precedes the cleanup of
	 * everything it depends on. The work it is draining is writes *through*
	 * these: a rotated refresh token going into the store, an audit event going
	 * into the sink. An adapter that closed its client first would fail the
	 * write this drain exists to wait for.
	 *
	 * `optional`, not `requires`, because a deployment that installs the
	 * package and leaves the feature off must still boot with none of them —
	 * and an optional key produces the same ordering edge whenever a *module*
	 * fills it. A slot filled from `bootstrapComponents` is the host's own
	 * value, which the boot planner neither orders nor disposes of, so there is
	 * nothing to be ordered against.
	 */
	optional: ["federationGrantStore", "subjectRevocation", "auditSink"] as const,
	provides: {
		federationGrantBackground: () => createFederationGrantBackground(),
	},
	lifecycle: {
		federationGrantBackground: {
			cleanup: (background) => background.drain(),
		},
	},
});

export const federationGrantsModule = defineModule({
	name: "federation-grants",
	configSchema: federationGrantsConfigSchema,
	requires: ["config", "federationGrantBackground", "clientRepository"] as const,
	optional: [
		"federationGrantStore",
		"rateLimiter",
		"auditSink",
		"subjectRevocation",
		"replaySeenSet",
		"logger",
		"federationProviders",
	] as const,
	contributes: {
		routes: [
			(deps: AnyDeps) => {
				if (!isEnabled(deps)) {
					// Nothing below this line is read: not a component, not a
					// connection, not the rest of the configuration. That is the
					// whole of what `enabled = false` promises.
					return {
						id: "federation-grants",
						mountPath: FEDERATION_GRANTS_MOUNT_PATH,
						handler: createDisabledFederationGrantRouter(),
					};
				}
				// In §5's order, so that the most fundamental omission is the one
				// an operator is told about: a deployment with no store has not
				// half-configured the feature, it has not configured it.
				const store = requireStore(deps);
				// Second, because it is the same question asked of the other
				// half: a grant that can be read from somewhere and ended
				// nowhere is worse than one that cannot be read at all. Slice 4
				// answered this per request, with a bridge that threw; a
				// composition error belongs at boot, where a deployment finds
				// out before it has told a user it was set up.
				const revocation = requireFederationGrantSubjectRevocation({
					module: "federationGrantsModule",
					subjectRevocation: deps.subjectRevocation,
					federationGrantStore: store,
				});
				const rateLimiter = requireLimiter(deps);
				const failMode = requireFailMode(deps);
				const limits = resolveFederationGrantRetrievalLimits(deps.config);
				const connections = resolveFederationGrantConnections(deps.config);
				requireDelegatedCapability(deps, connections);
				requireAuditDecision(deps);
				return {
					id: "federation-grants",
					mountPath: FEDERATION_GRANTS_MOUNT_PATH,
					handler: createFederationGrantRouter({
						store,
						connections,
						refresher: refresherFor(deps),
						grantsBoundary: boundaryFor(revocation),
						limits,
						background: deps.federationGrantBackground,
						clientRepository: deps.clientRepository,
						issuer: deps.config.oauth.jwt.issuer,
						rateLimiter,
						failMode,
						...(deps.replaySeenSet === undefined ? {} : { replaySeenSet: deps.replaySeenSet }),
						...(deps.auditSink === undefined ? {} : { auditSink: deps.auditSink }),
						...(deps.logger === undefined ? {} : { logger: deps.logger }),
					}),
				};
			},
		],
	},
});

/**
 * The documented installation form: `modules: [...federationGrantsModules]`.
 * The registry first, though the planner would sort them anyway — reading it
 * in dependency order is how the pair explains itself at a composition root.
 */
export const federationGrantsModules = [
	federationGrantBackgroundModule,
	federationGrantsModule,
] as const;
