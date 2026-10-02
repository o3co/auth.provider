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
 * `POST /oauth/federation-grants/:grantId/status`: a grant's lifecycle, kept
 * apart from the token route's issuance. See README, "The routes a client
 * calls", and ADR 2026-09-17-federation-grants-offline-delegation, D9.
 *
 * `inspect` only, never `open`, a refresh, the refresh lock or `touch`: opening
 * a dashboard must not rotate a credential at an upstream, and `lastUsedAt`
 * must not record a look as a use. Its one write is a backstop revocation it
 * finds, persisted and audited: one only computed would be computed again by
 * every later reader and would vanish the day the boundary is lost.
 *
 * A `503` is one line at error, `federation_grant_status_unavailable`, with
 * `reason`, `store` and `step`. A stored date the view cannot put on the wire
 * is the record's outage, `503` `storage`, as retrieval answers it. A boundary that could not be read for a grant
 * answered from the record is one warn, `federation_grant_status_step_failed`.
 */

import {
	type AuditSink,
	type EffectiveFederationGrantStatus,
	effectiveFederationGrantStatus,
	type FederationGrantConnection,
	type FederationGrantRetrievalLimits,
	type FederationGrantStore,
	type FederationGrantWrite,
	federationGrantAuditMetadata,
	type Logger,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { createFederationGrantAuditBridge } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { createFederationGrantLog } from "./log.mjs";
import { parseFederationGrantStatusRequest } from "./parse.mjs";
import { allows } from "./permission.mjs";
import { requestIdOf } from "./requestId.mjs";
import { federationGrantStatusView } from "./statusView.mjs";

export interface FederationGrantStatusHandlerOptions {
	readonly store: FederationGrantStore;
	readonly connections: ReadonlyMap<string, FederationGrantConnection>;
	readonly grantsBoundary: (subject: string) => Promise<Date | null>;
	readonly limits: FederationGrantRetrievalLimits;
	readonly background: FederationGrantBackground;
	readonly now?: () => Date;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
}

/** The same body every ownership failure answers with, byte for byte. */
const NOT_FOUND = { error: "grant_not_found" } as const;
const UNAVAILABLE = (reason: string) => ({
	error: "temporarily_unavailable",
	error_description: reason,
});

export function createFederationGrantStatusHandler(
	options: FederationGrantStatusHandlerOptions,
): RequestHandler {
	const now = options.now ?? (() => new Date());
	const log = createFederationGrantLog(options.logger);

	return async (req, res) => {
		const correlationId = requestIdOf(res);
		const matched = req.params.grantId;
		const grantId = typeof matched === "string" ? matched : "";
		const client = (req as { oauthClient?: { clientId: string } }).oauthClient;
		const audit = createFederationGrantAuditBridge({
			...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
			...(req.ip === undefined ? {} : { ip: req.ip }),
			...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
			operation: "status",
			now,
		});

		/** A `503` this route answers: one line, at error. */
		const unavailable = (
			reason: "storage" | "key_unavailable",
			at?: { readonly store: string; readonly step: string; readonly error: unknown },
		): void => {
			const fields = { grantId, correlationId, reason, store: at?.store, step: at?.step };
			if (at === undefined) log.outage("federation_grant_status_unavailable", fields);
			else log.outage("federation_grant_status_unavailable", fields, at.error);
			res.status(503).json(UNAVAILABLE(reason));
		};
		// A boundary that could not be read is logged by whichever exit it
		// reaches: as the outage when it is what the 503 is for, and as a
		// failure the answer did not need otherwise.
		let boundaryFailure: { readonly error: unknown } | undefined;
		let boundaryAnswered = false;

		const release = options.background.admit();
		if (release === undefined) {
			res.status(503).json({ error: "service_unavailable", error_description: "shutting_down" });
			return;
		}

		try {
			const parsed = parseFederationGrantStatusRequest(req.body);
			if (!parsed.ok) {
				res.status(400).json({ error: "invalid_request", error_description: parsed.description });
				return;
			}
			if (client === undefined) {
				res.status(500).json({ error: "server_error" });
				return;
			}

			// Settled rather than awaited: a boundary that cannot be read is not
			// yet an answer. A grant that is already revoked, or not yet
			// consented to, is described from the record — and a 503 there would
			// hide the one thing the caller most needs to know.
			let boundary: Date | null | undefined;
			try {
				boundary = await options.grantsBoundary(parsed.value.subject);
				if (boundary !== null && !(boundary instanceof Date && !Number.isNaN(boundary.getTime()))) {
					throw new TypeError("the grants boundary is neither a date nor null");
				}
			} catch (error) {
				boundaryFailure = { error };
			}

			// Its own failure, not the handler's: a store that is down is an
			// outage a caller should come back from, and the outer catch would
			// call it a programming error.
			let inspection: Awaited<ReturnType<FederationGrantStore["inspect"]>>;
			try {
				inspection = await options.store.inspect(grantId, now());
			} catch (error) {
				unavailable("storage", { store: "federation_grant", step: "inspect", error });
				return;
			}
			// Sampled after both reads: the status is judged at an instant no
			// earlier than the data it is judged from.
			const at = now();

			if (
				inspection === null ||
				inspection.grant.subject !== parsed.value.subject ||
				inspection.grant.clientId !== client.clientId
			) {
				// An unknown id, another client's grant and another subject's are
				// one answer, so that a caller can neither enumerate ids nor
				// discover whose they are.
				res.status(404).json(NOT_FOUND);
				return;
			}

			const grant = inspection.grant;
			const connection = options.connections.get(grant.connection);
			const maxExpiresInMs = options.limits.maxExpiresInMs;

			const permitted = (): boolean => allows(req, grant.connection);
			/** The view, `200`; a stored date it cannot put on the wire is the record's outage, `503`. */
			const describe = (status: EffectiveFederationGrantStatus, allowed: boolean): void => {
				const described = federationGrantStatusView(grant, status, maxExpiresInMs, allowed);
				if (!described.ok) {
					unavailable("storage", {
						store: "federation_grant",
						step: "inspect",
						error: new TypeError(`the stored grant holds no instant for ${described.field}`),
					});
					return;
				}
				res.status(200).json(described.view);
			};
			const refusePermission = (): void => {
				res
					.status(403)
					.json({ error: "access_denied", error_description: "connection_not_permitted" });
			};

			// Both are answered from the record, boundary or no boundary: a
			// revocation already written down needs nothing compared with it,
			// and a grant that has not been consented to has no consent to date.
			if (grant.status === "revoked") {
				// Terminal, so the allowlist does not decide WHETHER to answer: a
				// client whose registration changed can still be told that the
				// grant it used to spend is over, which is the answer that lets
				// it stop asking. It does decide WHAT is answered — see
				// `federationGrantStatusView`.
				describe({ status: "revoked", reason: grant.revocation.by }, permitted());
				return;
			}
			if (grant.status === "pending") {
				// NOT terminal. A pending grant has not started rather than
				// ended, so describing it is the ordinary authorization question.
				if (!permitted()) {
					refusePermission();
					return;
				}
				describe({ status: "pending" }, true);
				return;
			}
			if (boundaryFailure !== undefined) {
				boundaryAnswered = true;
				unavailable("storage", {
					store: "revocation_boundary",
					step: "read",
					error: boundaryFailure.error,
				});
				return;
			}

			const status = effectiveFederationGrantStatus(grant, {
				now: at,
				connection,
				maxExpiresInMs,
				// `undefined` never reaches here from the module's bridge, which
				// refuses an answer that is neither; a hand-mounted reader that
				// returns one is treated as a failure above rather than as "nothing
				// was revoked".
				grantsBoundary: boundary ?? null,
				revocationSkewMs: options.limits.revocationSkewMs,
				// A key that is not in the ring is not a status — it is an outage,
				// answered below and only where it would otherwise have read as a
				// credential that cannot be opened.
				credentials: inspection.credentials === "ok" ? "ok" : "unreadable",
			});

			if (status.status === "revoked" && status.reason === "backstop") {
				// Persisted, not merely reported (see the file comment). The event
				// is built from the record this write returned: a reauthorization
				// landing between the `inspect` above and this write would
				// otherwise have it describe access that was not the access ended.
				let written: FederationGrantWrite;
				try {
					written = await options.store.revoke(grantId, "backstop", at);
				} catch (error) {
					unavailable("storage", { store: "federation_grant", step: "revoke", error });
					return;
				}
				// A write that changed nothing — another reader got there first —
				// still permits the answer; it is simply not this call's event.
				if (written.ok) {
					options.background.register(
						audit({
							type: "federation.grant.revoked",
							correlationId,
							grantId,
							clientId: client.clientId,
							subject: written.grant.subject,
							...federationGrantAuditMetadata(written.grant),
							outcome: "backstop",
						}),
					);
				}
			}

			// Terminal facts are reported before the connection allowlist is
			// consulted: a client whose registration changed can still be told
			// that the grant it used to spend is over, which is the answer that
			// lets it stop asking.
			if (status.status !== "revoked" && status.status !== "expired" && !permitted()) {
				refusePermission();
				return;
			}

			if (
				inspection.credentials === "key_unavailable" &&
				status.status === "reauthorization_required" &&
				status.reason === "credential_unreadable"
			) {
				// Only here. An outage must not mask a terminal answer, and
				// nothing reported ahead of this needs a credential at all.
				unavailable("key_unavailable");
				return;
			}

			describe(status, permitted());
		} catch (error) {
			log.unexpected("status", { grantId, correlationId }, error);
			res.status(500).json({ error: "server_error" });
		} finally {
			if (boundaryFailure !== undefined && !boundaryAnswered) {
				log.degraded(
					"federation_grant_status_step_failed",
					{ grantId, correlationId, store: "revocation_boundary", step: "read" },
					boundaryFailure.error,
				);
			}
			release();
		}
	};
}
