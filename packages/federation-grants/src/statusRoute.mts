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
 * `POST /oauth/federation-grants/:grantId/status` (#593, D9).
 *
 * Status describes a grant's lifecycle. Token answers an issuance request.
 * Keeping them apart is what this file is:
 *
 *  - **`inspect` only.** Never `open`, never a refresh, never the refresh
 *    lock, never `touch`. Calling retrieval from here would rotate a
 *    credential at an upstream because somebody opened a dashboard, and
 *    `lastUsedAt` would record a look as a use.
 *  - **200 for every effective status**, including expired and revoked. A
 *    successful inspection of a grant that has ended is a successful
 *    inspection; answering the token route's 410 would make a dashboard read
 *    "this call failed" for a grant that is simply over.
 *  - **It is not a health check for `/token`.** `inspect` reports whether the
 *    credential authenticates, not whether the upstream will issue something
 *    usable — so `active` does not promise a token, and an ineligible status
 *    can coexist with a perfectly usable cached one.
 *
 * Two things it does write. A backstop it finds is written down, because a
 * revocation only computed would be computed again by every later reader and
 * would vanish the day the boundary is lost. And that write is audited.
 */

import {
	type AuditSink,
	effectiveFederationGrantStatus,
	type FederationGrantConnection,
	type FederationGrantRetrievalLimits,
	type FederationGrantStore,
	type Logger,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { createFederationGrantAuditBridge } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { parseFederationGrantStatusRequest } from "./parse.mjs";
import { createSanitizedReporter } from "./report.mjs";
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
	const report = options.logger === undefined ? undefined : createSanitizedReporter(options.logger);

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
			let boundaryFailed = false;
			try {
				boundary = await options.grantsBoundary(parsed.value.subject);
			} catch (error) {
				boundaryFailed = true;
				report?.({ during: "boundary", error, grantId, correlationId });
			}

			const inspection = await options.store.inspect(grantId, now());
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

			if (grant.status === "revoked" || grant.status === "pending") {
				res
					.status(200)
					.json(
						federationGrantStatusView(
							grant,
							grant.status === "revoked"
								? { status: "revoked", reason: grant.revocation.by }
								: { status: "pending" },
							maxExpiresInMs,
						),
					);
				return;
			}
			if (boundaryFailed) {
				res.status(503).json(UNAVAILABLE("storage"));
				return;
			}

			const status = effectiveFederationGrantStatus(grant, {
				now: at,
				connection,
				maxExpiresInMs,
				grantsBoundary: boundary ?? null,
				revocationSkewMs: options.limits.revocationSkewMs,
				// A key that is not in the ring is not a status — it is an outage,
				// answered below and only where it would otherwise have read as a
				// credential that cannot be opened.
				credentials: inspection.credentials === "ok" ? "ok" : "unreadable",
			});

			if (status.status === "revoked" && status.reason === "backstop") {
				// Written down, not merely reported: a revocation that only ever
				// exists as a computation is recomputed by every later reader and
				// disappears the day the boundary is lost.
				let written: { readonly ok: boolean };
				try {
					written = await options.store.revoke(grantId, "backstop", at);
				} catch (error) {
					report?.({ during: "backstop_revoke", error, grantId, correlationId });
					res.status(503).json(UNAVAILABLE("storage"));
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
							subject: grant.subject,
							connection: grant.connection,
							outcome: "backstop",
						}),
					);
				}
			}

			// Terminal facts are reported before the connection allowlist is
			// consulted: a client whose registration changed can still be told
			// that the grant it used to spend is over, which is the answer that
			// lets it stop asking.
			if (status.status !== "revoked" && status.status !== "expired") {
				const allowed =
					(req as { oauthClient?: { allowedFederationGrantConnections?: readonly string[] } })
						.oauthClient?.allowedFederationGrantConnections ?? [];
				if (!allowed.includes(grant.connection)) {
					res
						.status(403)
						.json({ error: "access_denied", error_description: "connection_not_permitted" });
					return;
				}
			}

			if (
				inspection.credentials === "key_unavailable" &&
				status.status === "reauthorization_required" &&
				status.reason === "credential_unreadable"
			) {
				// Only here. An outage must not mask a terminal answer, and
				// nothing reported ahead of this needs a credential at all.
				res.status(503).json(UNAVAILABLE("key_unavailable"));
				return;
			}

			res.status(200).json(federationGrantStatusView(grant, status, maxExpiresInMs));
		} catch (error) {
			report?.({ during: "handler", error, grantId, correlationId });
			res.status(500).json({ error: "server_error" });
		} finally {
			release();
		}
	};
}
