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
 * `POST /oauth/federation-grants/:grantId/token` (#593, D9–D12).
 *
 * A shell around `retrieveFederationGrantToken`, and deliberately nothing
 * more. It adds transport, authentication, serialization, correlation and
 * audit; every decision about the grant itself is core's.
 *
 * ### What this must not do
 *
 * The mistake this design expects is an "obvious" authorization check placed
 * in FRONT of core — rejecting a client with no connection allowlist, or a
 * grant whose connection an operator removed, or one carrying an
 * ineligibility marker, before the retrieval is called. Each of those reads
 * as a tightening and each changes a settled answer:
 *
 *   - a revoked grant answers 410 whether or not the client may use its
 *     connection, because the user revoking it is the more useful truth; an
 *     allowlist check in front turns that into 403, which tells a caller the
 *     grant would work if their registration changed;
 *   - a grant with an ineligibility marker still has a usable cached token,
 *     and core serves it; refusing here withholds a token nothing is wrong
 *     with.
 *
 * Nor does it retry a denial (a "helpful" second attempt can cost a second
 * upstream rotation), recompute `expires_in`, turn an unmet `min_ttl` into an
 * error, reclassify an upstream's refusal, manage locks, add a timeout that
 * abandons the retrieval's worker, delete a credential it could not read, or
 * look in another grant or in the session-bound token store.
 *
 * It does not read `lastLook` either. That is core's private orchestration.
 *
 * ### What it logs
 *
 * Core tells this route every failure it turns into an answer or drops
 * (`report`), and a `503` carries the one it was turned from (`failure`). The
 * route holds what it is told until the answer is in: the failure the `503`
 * carries is the outage, written once at error as
 * `federation_grant_token_unavailable`; every other one — and whatever is
 * told after the answer, the tail of a refresh — is one warn,
 * `federation_grant_token_step_failed`. A `503` for contention (`lock_timeout`,
 * `concurrent_update`) is a warn too, `federation_grant_token_contended`:
 * nothing is down.
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
	 * The subject's grants boundary (D13). Throwing is the honest answer when
	 * the deployment has no subject-revocation capability: `null` would say
	 * "nothing was revoked", which is not something an absent boundary knows.
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

/** Where a retrieval failed, as a line names it: the step core names, and its store. */
const where = (failure: FederationGrantRetrievalFailure) => ({
	store: STORE_OF[failure.during],
	step: failure.during,
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
		// Opaque: an ID is whatever created it, and imposing the acquisition
		// generator's shape on it would refuse every record a deployment seeded
		// before that generator existed.
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
					// Absent means nothing is allowed: a client registered before
					// offline delegation existed does not find itself opted into it.
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
			if (!result.ok && result.code === "temporarily_unavailable") {
				flush(result.failure);
				unavailable(result);
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
