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
 * Core's audit events carried to the deployment's sink (#593, D18).
 *
 * **The sink's promise is returned, not detached.** `emitAuditEvent` — which
 * every other module-side emission goes through — calls `sink.record(event)`
 * and swallows the promise. That is right where the emitter is answering a
 * request and will be gone before the sink settles; it is wrong here, because
 * core bounds its own audit waits and hands them to the background registry,
 * and a promise nobody holds is one a shutdown cannot drain. The event most
 * often lost that way is the audit of a refresh that landed after the
 * response — the one an operator goes looking for.
 *
 * **Core's omissions are preserved.** For a grant that is unknown to the
 * caller, or one that was never authorized, core supplies no connection, no
 * upstream and no scopes. This does not read them: for the never-authorized
 * case there is nothing to read, and for the unknown-grant case a read would
 * answer the question that the identical 404 exists to refuse.
 *
 * The outcome is copied as core built it. It needs no sanitizing here because
 * core no longer builds one from an unchecked stored code — the allow-list is
 * applied where the reason is constructed (D11), which is the only place a
 * mutation pass can hold it.
 */

import type { AuditEvent, AuditSink, FederationGrantAuditEvent } from "@o3co/auth-provider-core";

export interface FederationGrantAuditBridgeOptions {
	/** Absent on a deployment that declared `audit.sink.type = "none"`. */
	readonly sink?: AuditSink;
	readonly ip?: string;
	readonly userAgent?: string;
	/** Which route the event came from: status writes a backstop revocation too. */
	readonly operation: "token" | "status";
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
			subject: event.subject,
			clientId: event.clientId,
			...(options.ip === undefined ? {} : { ip: options.ip }),
			...(options.userAgent === undefined ? {} : { userAgent: options.userAgent }),
			details: {
				correlationId: event.correlationId,
				grantId: event.grantId,
				...(event.connection === undefined ? {} : { connection: event.connection }),
				// Copies, so that a sink which holds its argument cannot be
				// handed a reference into a record core is still working with.
				...(event.upstream === undefined ? {} : { upstream: { ...event.upstream } }),
				...(event.resource === undefined ? {} : { resource: event.resource }),
				...(event.scopes === undefined ? {} : { scopes: [...event.scopes] }),
				outcome: event.outcome,
				operation,
			},
		};
		// A sink that throws, rejects or never answers skips no write, holds no
		// lock and delays no answer — core's contract, and it holds only if a
		// synchronous throw here does not become the request's 500.
		try {
			await sink.record(mapped);
		} catch {
			// Deliberately silent: the reporter is the operator-visible channel
			// for a failure, and a sink outage that logged through the sink
			// would be the outage reporting itself.
		}
	};
}

export interface RouteDeniedEventInput {
	readonly correlationId: string;
	readonly grantId: string;
	/** A fixed identifier: `invalid_request`, `invalid_client`, `rate_limited/provider`, … */
	readonly outcome: string;
	/** Only once client authentication has established it. */
	readonly clientId?: string;
	/** Only once the body has been parsed; it is an assertion, not an identity. */
	readonly subject?: string;
}

/**
 * A `.token.denied` for an exit that never reached core: a body that would not
 * parse, an authentication that failed, this provider's own throttle, a
 * request admitted as the process began to shut down.
 *
 * `clientId` and `subject` are empty until each has been established. Before
 * authentication there is a Basic username and an assertion `iss` on the
 * request, and neither has been verified — promoting one into `clientId` puts
 * an unauthenticated caller's claim into the field an operator reads as "this
 * client did it".
 */
export function routeDeniedEvent(input: RouteDeniedEventInput): FederationGrantAuditEvent {
	return {
		type: "federation.grant.token.denied",
		correlationId: input.correlationId,
		grantId: input.grantId,
		clientId: input.clientId ?? "",
		subject: input.subject ?? "",
		outcome: input.outcome,
	};
}
