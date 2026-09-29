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
 * `POST /oauth/federation-grants/:grantId/token`: a shell around
 * `retrieveFederationGrantToken` that adds transport, authentication,
 * serialization, correlation and audit. Every decision about the grant is core's.
 *
 * Do not add authorization checks in front of core (connection allowlist, removed
 * connection, ineligibility marker). Each changes a settled answer: core
 * answers another client or subject `grant_not_found` first, and for the owning
 * client a revoked grant answers 410 ahead of its connection allowlist, where a
 * 403 in front would suggest the grant works under another registration; a
 * grant with an ineligibility marker may still have a usable cached token, which
 * core serves.
 * Nor may this route retry a denial (a second attempt can cost a second upstream
 * rotation), recompute `expires_in`, turn an unmet `min_ttl` into an error,
 * reclassify an upstream refusal, manage locks, abandon the retrieval's worker on
 * a timeout of its own, delete an unreadable credential, read `lastLook`, or look
 * in another grant or the session-bound token store.
 *
 * Logging: core reports every failure it turns into an answer or drops
 * (`report`), and a `503` carries the one it came from (`failure`). Reports are
 * held until the answer is in; the carried one is the outage, logged once at error
 * as `federation_grant_token_unavailable`, every other one (and any reported
 * afterwards by a refresh tail) is a `federation_grant_token_step_failed` warn. A
 * contention `503` (`lock_timeout`, `concurrent_update`) is the warn
 * `federation_grant_token_contended`: nothing is down.
 */

import {
	type AuditSink,
	type FederationGrantConnection,
	type FederationGrantRefresher,
	type FederationGrantRetrievalFailure,
	type FederationGrantRetrievalLimits,
	type FederationGrantStore,
	type FederationGrantTokenResult,
	type Logger,
	retrieveFederationGrantToken,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { markHandlerReached } from "./denialAudit.mjs";
import { createFederationGrantLog } from "./log.mjs";
import { parseFederationGrantTokenRequest } from "./parse.mjs";
import { allowedConnectionsOf } from "./permission.mjs";
import { requestIdOf } from "./requestId.mjs";
import { serializeFederationGrantTokenResult } from "./serialize.mjs";

export interface FederationGrantTokenHandlerOptions {
	readonly store: FederationGrantStore;
	/** The connections as they are configured NOW; a removed one is simply absent. */
	readonly connections: ReadonlyMap<string, FederationGrantConnection>;
	readonly refresher: (
		connection: FederationGrantConnection,
	) => FederationGrantRefresher | undefined;
	/**
	 * The subject's grants boundary. Throw when the deployment has no
	 * subject-revocation capability: `null` would claim nothing was revoked.
	 */
	readonly grantsBoundary: (subject: string) => Promise<Date | null>;
	readonly limits: FederationGrantRetrievalLimits;
	readonly background: FederationGrantBackground;
	readonly now?: () => Date;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
}

/**
 * The store a retrieval step asks, for the `store` field: the grant store,
 * or the subject's grants boundary. Absent for a step that asks neither —
 * the upstream, the audit sink, the drain's registry.
 */
const STORE_OF: Readonly<Partial<Record<FederationGrantRetrievalFailure["during"], string>>> = {
	boundary: "revocation_boundary",
	// A boundary that cannot be compared: what the boundary store answered.
	status: "revocation_boundary",
	open: "federation_grant",
	backstop_revoke: "federation_grant",
	lock: "federation_grant",
	release: "federation_grant",
	mark: "federation_grant",
	write: "federation_grant",
	touch: "federation_grant",
};

/**
 * Where a retrieval failed, as a line names it: the step core names, its
 * store, and — for a retried write — how many attempts failed so.
 */
const where = (failure: FederationGrantRetrievalFailure) => ({
	store: STORE_OF[failure.during],
	step: failure.during,
	attempts: failure.attempts,
});

/** The reasons a `503` is contention rather than an outage: nothing is down. */
const CONTENTION: ReadonlySet<string> = new Set(["lock_timeout", "concurrent_update"]);

/** The body every exit of this package answers with, and the header it may carry. */
interface Answer {
	readonly status: number;
	readonly body: Readonly<Record<string, unknown>>;
	readonly retryAfterSeconds?: number;
}

export function createFederationGrantTokenHandler(
	options: FederationGrantTokenHandlerOptions,
): RequestHandler {
	const now = options.now ?? (() => new Date());
	const log = createFederationGrantLog(options.logger);

	return async (req, res) => {
		// From here on this handler owns the denial; the chain's exit hook stands
		// down so that one refusal is one event.
		markHandlerReached(res);
		const correlationId = requestIdOf(res);
		// Opaque: an ID is whatever created it; imposing the acquisition generator's
		// shape would refuse records a deployment seeded otherwise.
		const matched = req.params.grantId;
		const grantId = typeof matched === "string" ? matched : "";
		const client = (req as { oauthClient?: { clientId: string } }).oauthClient;
		const audit = createFederationGrantAuditBridge({
			...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
			...(req.ip === undefined ? {} : { ip: req.ip }),
			...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
			operation: "token",
			now,
		});

		/** A denial this route decided, before core was ever called. */
		const deny = (answer: Answer, outcome: string, subject?: string): void => {
			options.background.register(
				audit(
					routeDeniedEvent({
						correlationId,
						grantId,
						outcome,
						...(client === undefined ? {} : { clientId: client.clientId }),
						...(subject === undefined ? {} : { subject }),
					}),
				),
			);
			send(answer);
		};

		const send = (answer: Answer): void => {
			if (answer.retryAfterSeconds !== undefined) {
				res.set("Retry-After", String(answer.retryAfterSeconds));
			}
			res.status(answer.status).json(answer.body);
		};

		/** A failure the answer did not carry: one warn. */
		const stepFailed = (failure: FederationGrantRetrievalFailure): void =>
			log.degraded(
				"federation_grant_token_step_failed",
				{ grantId, correlationId, ...where(failure) },
				failure.error,
			);
		// Held until the answer is in, when it is known which one — if any —
		// the answer carries; told after it, a failure is the tail's.
		const held: FederationGrantRetrievalFailure[] = [];
		let answered = false;
		const report = (failure: FederationGrantRetrievalFailure): void => {
			if (answered) stepFailed(failure);
			else held.push(failure);
		};
		/** The held failures, each once, but the one the answer carries. */
		const flush = (carried?: FederationGrantRetrievalFailure): void => {
			answered = true;
			for (const failure of held.splice(0)) if (failure !== carried) stepFailed(failure);
		};
		/** A `503`: the outage once, at error — or contention, at warn. */
		const unavailable = (
			result: Extract<FederationGrantTokenResult, { code: "temporarily_unavailable" }>,
		): void => {
			const { reason, retryAfterSeconds, failure } = result;
			const fields = {
				grantId,
				correlationId,
				reason,
				...(failure === undefined ? {} : where(failure)),
				retryAfterSeconds,
			};
			const cause: [] | [unknown] = failure === undefined ? [] : [failure.error];
			if (CONTENTION.has(reason))
				log.degraded("federation_grant_token_contended", fields, ...cause);
			else log.outage("federation_grant_token_unavailable", fields, ...cause);
		};

		// Admitted, or refused: a request let in after the drain has begun would
		// start an upstream refresh that nothing is waiting for.
		const release = options.background.admit();
		if (release === undefined) {
			deny(
				{
					status: 503,
					body: { error: "service_unavailable", error_description: "shutting_down" },
				},
				"service_unavailable/shutting_down",
			);
			return;
		}

		try {
			const parsed = parseFederationGrantTokenRequest(req.body);
			if (!parsed.ok) {
				deny(
					{
						status: 400,
						body: { error: "invalid_request", error_description: parsed.description },
					},
					"invalid_request",
				);
				return;
			}
			if (client === undefined) {
				// Unreachable through the router, which authenticates first; a
				// hand-mounted handler that forgot to is a composition error and
				// not something to answer as if the caller were anonymous.
				deny({ status: 500, body: { error: "server_error" } }, "server_error");
				return;
			}

			const result = await retrieveFederationGrantToken(
				{
					store: options.store,
					connection: (name) => options.connections.get(name),
					refresher: options.refresher,
					grantsBoundary: options.grantsBoundary,
					now,
					limits: options.limits,
					background: (work) => options.background.register(work),
					audit,
					report,
				},
				{
					grantId,
					clientId: client.clientId,
					subject: parsed.value.subject,
					// Absent means nothing is allowed: a client registered without the field is not
					// opted into offline delegation.
					allowedConnections: allowedConnectionsOf(req),
					correlationId,
					...(parsed.value.connection === undefined ? {} : { connection: parsed.value.connection }),
					...(parsed.value.scope === undefined ? {} : { scope: parsed.value.scope }),
					...(parsed.value.resource === undefined ? {} : { resource: parsed.value.resource }),
					...(parsed.value.minTtlSeconds === undefined
						? {}
						: { minTtlSeconds: parsed.value.minTtlSeconds }),
				},
			);
			// The outage first, then what the answer did not carry.
			if (!result.ok && result.code === "temporarily_unavailable") {
				unavailable(result);
				flush(result.failure);
			} else {
				flush();
			}
			// Core has already audited what it decided. A second event here would
			// double every outcome in an operator's dashboard.
			send(serializeFederationGrantTokenResult(result));
		} catch (error) {
			// Core did not conclude, so nothing audited this — which makes it the
			// one failure the route owns.
			flush();
			log.unexpected("token", { grantId, correlationId }, error);
			deny({ status: 500, body: { error: "server_error" } }, "server_error");
		} finally {
			release();
		}
	};
}
