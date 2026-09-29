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
 * Core's audit events carried to the deployment's sink (the federation-grants
 * ADR, D18; README, "What is audited, and where it goes").
 *
 * **The sink's promise is returned, not detached**, unlike `emitAuditEvent`:
 * core bounds its own audit waits and hands them to the background registry,
 * and a promise nobody holds is one a shutdown cannot drain — typically the
 * audit of a refresh that landed after the response.
 *
 * **Core's omissions are preserved.** For a grant unknown to the caller, or
 * never authorized, core supplies no connection, upstream or scopes, and this
 * does not read them: for an unknown grant a read would answer the question
 * the identical 404 exists to refuse. The outcome is copied as core built it;
 * core applies the allow-list where the reason is constructed.
 *
 * **A caller's own text is bounded.** The grant id and the subject the body
 * asserts go through core's `auditErrorText`; the request's `ip` and
 * `userAgent` are bounded by `recordAuditEvent` itself.
 */

import {
	type AuditEvent,
	type AuditSink,
	auditErrorText,
	type FederationGrantAuditEvent,
	recordAuditEvent,
} from "@o3co/auth-provider-core";

export interface FederationGrantAuditBridgeOptions {
	/** Absent on a deployment that declared `audit.sink.type = "none"`. */
	readonly sink?: AuditSink;
	readonly ip?: string;
	readonly userAgent?: string;
	/** Which route the event came from: status writes a backstop revocation too. */
	readonly operation: "token" | "status" | "revoke" | "request" | "connect";
	/** Sampled when the event is handed over, not when the request arrived. */
	readonly now: () => Date;
}

/**
 * The `audit` seam of `RetrieveFederationGrantTokenDeps`, and what the status
 * route's backstop write goes through.
 */
export function createFederationGrantAuditBridge(
	options: FederationGrantAuditBridgeOptions,
): (event: FederationGrantAuditEvent) => Promise<void> {
	const { sink, operation, now } = options;
	return async (event) => {
		if (sink === undefined) return;
		const mapped: AuditEvent = {
			timestamp: now(),
			type: event.type,
			subject: auditErrorText(event.subject),
			clientId: event.clientId,
			...(options.ip === undefined ? {} : { ip: options.ip }),
			...(options.userAgent === undefined ? {} : { userAgent: options.userAgent }),
			details: {
				correlationId: event.correlationId,
				grantId: auditErrorText(event.grantId),
				...(event.connection === undefined ? {} : { connection: event.connection }),
				// Copies, so that a sink which holds its argument cannot be
				// handed a reference into a record core is still working with.
				// Projected, not spread: the established pair and nothing else an
				// object handed in might carry.
				...(event.upstream === undefined
					? {}
					: { upstream: { issuer: event.upstream.issuer, subject: event.upstream.subject } }),
				...(event.resource === undefined ? {} : { resource: event.resource }),
				...(event.scopes === undefined ? {} : { scopes: [...event.scopes] }),
				outcome: event.outcome,
				operation,
			},
		};
		// A sink that throws, rejects or never answers skips no write, holds no
		// lock and delays no answer — but that is core's doing: core settles this
		// promise, bounds the wait and reports a failure through `report`, so it
		// must not be swallowed here. Awaiting it also turns a synchronous throw
		// into a rejection, so both failures look the same to whoever is waiting.
		await recordAuditEvent(sink, mapped);
	};
}

export interface RouteDeniedEventInput {
	/**
	 * Defaults to the token route's. A refused withdrawal is its own type: a
	 * dashboard counting denied disclosures would otherwise count them
	 * together, and they mean opposite things — one is a credential not handed
	 * out, the other a credential still live that somebody tried to end.
	 */
	readonly type?:
		| "federation.grant.token.denied"
		| "federation.grant.revoke.denied"
		| "federation.grant.request.denied"
		| "federation.grant.authorization_failed";
	readonly correlationId: string;
	readonly grantId: string;
	/** A fixed identifier: `invalid_request`, `invalid_client`, `rate_limited/provider`, … */
	readonly outcome: string;
	/** Only once client authentication has established it. */
	readonly clientId?: string;
	/** Only once the body has been parsed; it is an assertion, not an identity. */
	readonly subject?: string;
	/** The connection a connect flow was for, once its intent is known. */
	readonly connection?: string;
}

/**
 * A `.token.denied` for an exit that never reached core: a body that would not
 * parse, an authentication that failed, this provider's own throttle, a
 * request admitted as the process began to shut down.
 *
 * `clientId` and `subject` are empty until each has been established: before
 * authentication the Basic username and an assertion `iss` are unverified,
 * and `clientId` is the field an operator reads as "this client did it".
 */
export function routeDeniedEvent(input: RouteDeniedEventInput): FederationGrantAuditEvent {
	return {
		type: input.type ?? "federation.grant.token.denied",
		correlationId: input.correlationId,
		grantId: input.grantId,
		clientId: input.clientId ?? "",
		subject: input.subject ?? "",
		...(input.connection === undefined ? {} : { connection: input.connection }),
		outcome: input.outcome,
	};
}
