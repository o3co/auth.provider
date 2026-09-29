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
 * `POST /oauth/federation-grants/:grantId/revoke`: the owning client ends its
 * own grant. See README, "The routes a client calls", and ADR
 * 2026-09-17-federation-grants-offline-delegation, D9 and D13.
 *
 * **Ownership is the whole check.** Nothing that decides whether a credential
 * may be *disclosed* (connection allowlist or configuration, revision,
 * eligibility, expiry, boundary) is a reason to refuse a withdrawal. It reads
 * with `find`, not `open` or `inspect`, so a credential that will not open does
 * not keep a grant alive. A repeat answers 204 too: the record stays as a
 * tombstone for the status route. It does not stamp either subject boundary,
 * cascade sessions, touch the subject's other grants, call the upstream, take
 * the refresh lock or compute an effective status.
 *
 * A grant store that cannot be read or written is `503`, logged once at error
 * as `federation_grant_revoke_unavailable` with the `step` that failed.
 */

import {
	type AuditSink,
	type FederationGrant,
	type FederationGrantStore,
	federationGrantAuditMetadata,
	type Logger,
} from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { markHandlerReached } from "./denialAudit.mjs";
import { createFederationGrantLog } from "./log.mjs";
import { parseFederationGrantRevokeRequest } from "./parse.mjs";
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

		/** The grant store could not answer `step`: one line at error, and the 503. */
		const unavailable = (step: "find" | "revoke", error: unknown, subject: string): void => {
			log.outage(
				"federation_grant_revoke_unavailable",
				{ grantId, correlationId, reason: "storage", store: "federation_grant", step },
				error,
			);
			deny(
				503,
				{ error: "temporarily_unavailable", error_description: "storage" },
				"temporarily_unavailable/storage",
				subject,
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
				unavailable("find", error, subject);
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
				unavailable("revoke", error, subject);
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
						// caller claimed — including what access it was: the
						// upstream account, the resource and the scopes that
						// have just been taken away. The record may be a
						// tombstone by the time anybody reads this.
						subject: written.grant.subject,
						...federationGrantAuditMetadata(written.grant),
						outcome: "client",
					}).catch(() => undefined),
				);
			}
			res.status(204).end();
		} catch (error) {
			log.unexpected("revoke", { grantId, correlationId }, error);
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
