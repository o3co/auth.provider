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
 * `POST /oauth/federation-grants/:grantId/revoke` — the owning client ends its
 * own grant (#593, D9, D13).
 *
 * The route a backend calls when the integration is removed on its side: the
 * user disconnected the calendar, the workspace was deleted, the agent is
 * being decommissioned. Without it the only way to end a grant is a
 * subject-wide revocation, which ends everything else the user has too.
 *
 * **Ownership is the whole check.** The grant is this client's and this
 * subject's, or it is not there — and after that nothing else is consulted: no
 * connection allowlist, no current connection configuration, no revision, no
 * eligibility, no expiry, no boundary. Every one of those exists to decide
 * whether a credential may be *disclosed*, and none of them is a reason to
 * refuse a withdrawal. A grant whose connection was removed from the
 * configuration, whose encryption key is out of the ring, or which expired
 * last week and is still retained, is exactly the grant an operator most needs
 * to be able to end.
 *
 * It reads with `find` and not `open` or `inspect`: ownership lives on the
 * record, and a credential that will not open is not a reason to keep a grant
 * alive.
 *
 * **204, and nothing in the body.** A withdrawal has no result to report: the
 * grant is over. A second call answers 204 as well — the record is retained as
 * a tombstone for the status route, and a client retrying after a timeout must
 * not be told the second attempt failed.
 *
 * What it does NOT do: stamp either subject boundary, cascade sessions, touch
 * the subject's other grants, call the upstream, take the refresh lock, or
 * compute an effective status. Ending a grant here is a local fact about one
 * record. Revoking the upstream's own refresh token is the upstream's API and
 * a different failure domain — making a withdrawal depend on it would mean a
 * user cannot disconnect while somebody else's service is down.
 */

import type {
	AuditSink,
	FederationGrant,
	FederationGrantStore,
	Logger,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { markHandlerReached } from "./denialAudit.mjs";
import { parseFederationGrantRevokeRequest } from "./parse.mjs";
import { createSanitizedReporter } from "./report.mjs";
import { requestIdOf } from "./requestId.mjs";

export interface FederationGrantRevokeHandlerOptions {
	readonly store: FederationGrantStore;
	readonly background: FederationGrantBackground;
	readonly now?: () => Date;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
}

/** The same body an unknown id, another client's grant and another subject's all answer. */
const NOT_FOUND = { error: "grant_not_found" } as const;

export function createFederationGrantRevokeHandler(
	options: FederationGrantRevokeHandlerOptions,
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
			operation: "revoke",
			now,
		});
		// From here the denials are this handler's to emit, so the hook in
		// front of the chain does not count them a second time.
		markHandlerReached(res);

		/**
		 * A refusal, and the trail of it.
		 *
		 * `subject` is what the caller ASSERTED and `clientId` is what
		 * authentication established — never anything read off a record whose
		 * ownership has not been confirmed, because for a 404 that record
		 * belongs to somebody else.
		 */
		const deny = (
			status: number,
			body: Record<string, string>,
			outcome: string,
			subject?: string,
		): void => {
			res.status(status).json(body);
			options.background.register(
				audit(
					routeDeniedEvent({
						type: "federation.grant.revoke.denied",
						correlationId,
						grantId,
						outcome,
						...(client === undefined ? {} : { clientId: client.clientId }),
						...(subject === undefined ? {} : { subject }),
					}),
				).catch(() => undefined),
			);
		};

		const release = options.background.admit();
		if (release === undefined) {
			deny(
				503,
				{ error: "service_unavailable", error_description: "shutting_down" },
				"service_unavailable/shutting_down",
			);
			return;
		}

		try {
			const parsed = parseFederationGrantRevokeRequest(req.body);
			if (!parsed.ok) {
				deny(
					400,
					{ error: "invalid_request", error_description: parsed.description },
					`invalid_request/${parsed.description}`,
				);
				return;
			}
			const subject = parsed.value.subject;
			if (client === undefined) {
				// The middleware that establishes it answers on its own when it
				// fails, so reaching here means the chain was mounted wrongly.
				deny(
					500,
					{ error: "server_error", error_description: "unexpected_error" },
					"server_error/unexpected_error",
					subject,
				);
				return;
			}

			let grant: FederationGrant | null;
			try {
				grant = await options.store.find(grantId, now());
			} catch (error) {
				report?.({ during: "revoke_find", error, grantId, correlationId });
				deny(
					503,
					{ error: "temporarily_unavailable", error_description: "storage" },
					"temporarily_unavailable/storage",
					subject,
				);
				return;
			}

			if (grant === null || grant.subject !== subject || grant.clientId !== client.clientId) {
				// One answer for all three, so that a caller can neither
				// enumerate grant ids nor discover whose they are.
				deny(404, NOT_FOUND, "grant_not_found", subject);
				return;
			}

			if (grant.status === "revoked") {
				// Already over. Not a denial and not an event: nothing changed,
				// and a retry after a timeout is the ordinary way to get here.
				res.status(204).end();
				return;
			}

			let written: { readonly ok: true; readonly grant: FederationGrant } | { readonly ok: false };
			try {
				written = await options.store.revoke(grantId, "client", now());
			} catch (error) {
				report?.({ during: "revoke", error, grantId, correlationId });
				deny(
					503,
					{ error: "temporarily_unavailable", error_description: "storage" },
					"temporarily_unavailable/storage",
					subject,
				);
				return;
			}

			// `ok: false` is a write that changed nothing — somebody else ended
			// it between the read and here. The grant is over either way, which
			// is what the caller asked for; it is simply not this call's event.
			if (written.ok) {
				options.background.register(
					audit({
						type: "federation.grant.revoked",
						correlationId,
						grantId,
						clientId: client.clientId,
						// From the record the write returned, never from what the
						// caller claimed.
						subject: written.grant.subject,
						connection: written.grant.connection,
						outcome: "client",
					}).catch(() => undefined),
				);
			}
			res.status(204).end();
		} catch (error) {
			report?.({ during: "handler", error, grantId, correlationId });
			deny(
				500,
				{ error: "server_error", error_description: "unexpected_error" },
				"server_error/unexpected_error",
			);
		} finally {
			release();
		}
	};
}
