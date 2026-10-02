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
 * What every stage of the browser flow is handed: the router's options, and what
 * is derived from them once — the clock, the random ids, the log, admission's
 * dependencies for one request, and the audit of a failed flow. Admission's audit
 * writes and the failure audit are registered with the shutdown drain.
 */

import { randomBytes } from "node:crypto";
import {
	type AdmissionDeps,
	type AuditSink,
	type ClientRepository,
	type CsrfGuard,
	type FederationGrantAcquisitionConnection,
	type FederationGrantAuditEvent,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
	type FederationGrantStore,
	type Logger,
	type LoginEntry,
	type RateLimiter,
	recordAuditEvent,
	type SessionRequirementResolver,
	type SubjectRevocation,
	type SupportsDelegatedAuthorization,
	type UserRepository,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { createFederationGrantAuditBridge, routeDeniedEvent } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
import { createFederationGrantLog, type FederationGrantLog, type LogFields } from "./log.mjs";
import { requestIdOf } from "./requestId.mjs";

/**
 * What the connect flow needs of a federation: the authorization URL the consent
 * answer sends the user to, and the callback's code exchange. Refresh is the token
 * route's business.
 */
export type FederationGrantDelegatedAuthorizer = Pick<
	SupportsDelegatedAuthorization,
	"buildDelegatedAuthorizationUrl" | "exchangeDelegatedCode"
>;

export interface FederationGrantBrowserRouterOptions {
	readonly intentStore: FederationGrantIntentStore;
	readonly grantStore: FederationGrantStore;
	/**
	 * The `clientRepository` slot, which holds core's client-record boundary:
	 * each record it answers is validated and frozen, and a refused one rejects.
	 */
	readonly clientRepository: ClientRepository;
	/** The durable sessions behind the cookie, which admission re-reads at every step. */
	readonly userSessionStore: UserSessionStore;
	/**
	 * Where admission reads the subject's SESSIONS boundary, which a session must have
	 * authenticated after. The grants boundary is `grantsBoundary`.
	 */
	readonly subjectRevocation: SubjectRevocation;
	/**
	 * The `sessionRequirementResolver` the boot planner built (`resolverForTests` in
	 * tests): the session requirements admission asks. Admission refuses any other
	 * object.
	 */
	readonly requirements: SessionRequirementResolver;
	/** The clock-skew allowance the GRANTS boundary is compared with. */
	readonly revocationSkewMs: number;
	readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
	/** The federation's delegated authorizer, or `undefined` when it has none. */
	readonly authorizerFor: (federation: string) => FederationGrantDelegatedAuthorizer | undefined;
	/** `federation-grants.consent.url`: a path, or an absolute URL on the provider's origin. */
	readonly consentUrl: string;
	/**
	 * The login page a browser that is not signed in is sent to, and its
	 * `redirect_to` protocol: the session module's `loginEntry` slot.
	 */
	readonly login: Pick<LoginEntry, "urlFor">;
	/**
	 * The deployment's CSRF policy, the `csrfGuard` slot the session module
	 * provides: the consent answer is held to its request rule.
	 */
	readonly csrfGuard: Pick<CsrfGuard, "check">;
	/** `oauth.jwt.issuer`, held to core's `checkCanonicalIssuer`: every URL this router builds is built on it. */
	readonly issuer: string;
	/** The browser budget; its own `failMode` is the outage policy. */
	readonly rateLimiter: RateLimiter;
	readonly background: FederationGrantBackground;
	/**
	 * The subject's GRANTS boundary: what the callback's backstop and re-read
	 * compare a consent with.
	 */
	readonly grantsBoundary: (subject: string) => Promise<Date | null>;
	/** Callback check 5: whether the Store is asked who holds the upstream account. */
	readonly identityLookup: "required" | "unsupported";
	/** The port's own signature, not a copy of it, so the two cannot drift apart. */
	readonly userRepository?: Pick<UserRepository, "findSubjectByFederatedIdentity">;
	/** Milliseconds: where the code exchange is aborted (`upstreamHardTimeoutMs`). */
	readonly upstreamTimeoutMs: number;
	readonly now?: () => Date;
	/** 256 random bits, base64url. A seam for tests. */
	readonly randomId?: () => string;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
}

/**
 * What could not answer, for the one line an outage writes: the store (or
 * `client`, the client registry, which core's own line reports), what it was
 * asked, and what it threw. The session's part is admission's, which writes
 * its own line.
 */
export interface Unanswered {
	readonly store:
		| "federation_grant"
		| "federation_grant_intent"
		| "revocation_boundary"
		| "user_directory"
		| "client";
	readonly step: string;
	readonly error: unknown;
}

/** The browser half selects no `acr`: nothing asks for one here. */
const NO_ACR_TABLE: AdmissionDeps["acrTable"] = Object.freeze({});

/** What every stage is handed. */
export interface BrowserFlow {
	readonly options: FederationGrantBrowserRouterOptions;
	readonly now: () => Date;
	readonly randomId: () => string;
	readonly log: FederationGrantLog;
	readonly admissionFor: (flow: LogFields) => AdmissionDeps;
	readonly auditFor: (req: Request) => (event: FederationGrantAuditEvent) => Promise<void>;
	readonly failed: (
		req: Request,
		res: Response,
		outcome: string,
		intent?: FederationGrantIntent,
	) => void;
}

/**
 * The flow's shared part, derived once. `requirements` and `subjectRevocation` are
 * the ones the router has already checked.
 */
export function createBrowserFlow(
	options: FederationGrantBrowserRouterOptions,
	requirements: SessionRequirementResolver,
	subjectRevocation: SubjectRevocation,
): BrowserFlow {
	const now = options.now ?? (() => new Date());
	const randomId = options.randomId ?? (() => randomBytes(32).toString("base64url"));
	const log = createFederationGrantLog(options.logger);
	/**
	 * The deployment's audit sink with every write registered with the drain, so a
	 * shutdown also waits for the events admission records.
	 */
	const auditSink = options.auditSink;
	const drainedAuditSink: AuditSink | undefined =
		auditSink === undefined
			? undefined
			: {
					kind: auditSink.kind,
					record: (event) => {
						// Through core's `recordAuditEvent`, the one writer of a sink.
						const written = recordAuditEvent(auditSink, event);
						options.background.register(written.catch(() => undefined));
						return written;
					},
				};
	/**
	 * Admission's dependencies for one request: its logger is bound to the flow's
	 * grant, the request's correlation id and (at the consent) its method, so an
	 * outage line admission writes carries them too.
	 */
	const admissionFor = (flow: LogFields): AdmissionDeps => ({
		userSessionStore: options.userSessionStore,
		subjectRevocation,
		requirements,
		acrTable: NO_ACR_TABLE,
		logger: log.bound(flow),
		auditSink: drainedAuditSink,
		now,
	});

	const auditFor = (req: Request) =>
		createFederationGrantAuditBridge({
			...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
			...(req.ip === undefined ? {} : { ip: req.ip }),
			...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
			operation: "connect",
			now,
		});

	/** `federation.grant.authorization_failed`, with only what is established. */
	const failed = (req: Request, res: Response, outcome: string, intent?: FederationGrantIntent) => {
		options.background.register(
			auditFor(req)(
				routeDeniedEvent({
					type: "federation.grant.authorization_failed",
					// The FLOW's id once its intent is known — the one the lodging
					// request carried, so that every event of one flow correlates.
					// Before that there is only this request's own.
					correlationId: intent?.correlationId ?? requestIdOf(res),
					// An early failure has no grant to name, and none is invented.
					grantId: intent?.grantId ?? "",
					outcome,
					...(intent === undefined
						? {}
						: {
								clientId: intent.clientId,
								subject: intent.subject,
								connection: intent.connection,
							}),
				}),
			).catch(() => undefined),
		);
	};
	return { options, now, randomId, log, admissionFor, auditFor, failed };
}
