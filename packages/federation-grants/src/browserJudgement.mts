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
 * Whether this browser may go on with this intent now: session admission on the
 * cookie's claim as the step's action, then the flow's own conditions. Asked at
 * every step; fails closed, so a store that cannot answer is an outage, never a yes.
 */

import {
	type AdmissionDeps,
	admitSession,
	type FederationGrantBrowserBinding,
	type FederationGrantConnectTransaction,
	type FederationGrantIntent,
	federationGrantAllowlist,
	federationGrantAuthorizationRevision,
	federationGrantIdentityRevision,
	type SessionClaim,
	type UserSession,
} from "@o3co/auth-provider-core";
import type { Request } from "express";
import type { FederationGrantsAdmissionAction } from "./admissionActions.mjs";
import type { FederationGrantBrowserRouterOptions, Unanswered } from "./browserFlow.mjs";
import { sessionIdOf } from "./browserRequest.mjs";
import type { FederationGrantLog } from "./log.mjs";

export type Judgement =
	| { readonly ok: true; readonly binding: FederationGrantBrowserBinding }
	| {
			readonly ok: false;
			readonly status: number;
			/** A fixed identifier: what the audit carries, and what a navigation names. */
			readonly reason:
				| "subject_mismatch"
				| "reauthentication_required"
				| "stale"
				| "connection_not_permitted"
				| "connection_changed";
	  }
	| {
			readonly ok: false;
			readonly status: 503;
			readonly reason: "unavailable";
			/**
			 * What could not answer: the caller logs it, once. Absent when it was
			 * the session's part, whose line admission wrote.
			 */
			readonly unanswered?: Unanswered;
			/**
			 * When it was the session's part: the store admission named, described as core's
			 * `describeAdmissionOutage` does.
			 */
			readonly admissionStore?: string;
	  };

/** The admission action of each browser step, as the module registers it. */
export const CONNECT: FederationGrantsAdmissionAction = "federation_grants.connect";
export const CONSENT: FederationGrantsAdmissionAction = "federation_grants.consent";
export const CALLBACK: FederationGrantsAdmissionAction = "federation_grants.callback";

/**
 * The session's part of a judgement: the live record; `null` for any session a new
 * login is the remedy for (gone, expired, another subject's, covered by the
 * sessions boundary, or refused by a requirement, `step_up` included); or an
 * outage admission has already logged, with the store it named.
 */
async function admittedSession(
	deps: AdmissionDeps,
	claim: SessionClaim,
	action: FederationGrantsAdmissionAction,
): Promise<UserSession | null | { readonly unavailable: string }> {
	const admission = await admitSession(deps, { claim, action });
	if (admission.outcome === "unavailable") return { unavailable: admission.store };
	return admission.outcome === "admitted" ? admission.session : null;
}

/** Whether the session's part was an outage, rather than a record or a refusal. */
const isAdmissionOutage = (
	part: UserSession | null | { readonly unavailable: string },
): part is { readonly unavailable: string } => part !== null && "unavailable" in part;

/**
 * Whether THIS browser may go on with THIS intent now: the cookie names the
 * intent's subject, admission admits its session as `action`, the intent is still
 * the grant's current one, the client may still use the connection, and the
 * connection is unchanged since lodging. Asked at every step, so a revocation,
 * renewal or configuration change mid-flow stops a flow that has not finished.
 */
export async function judge(
	options: FederationGrantBrowserRouterOptions,
	admission: AdmissionDeps,
	req: Request,
	claim: SessionClaim,
	action: FederationGrantsAdmissionAction,
	intent: FederationGrantIntent,
	now: () => Date,
): Promise<Judgement> {
	if (claim.subject !== intent.subject) {
		return { ok: false, status: 403, reason: "subject_mismatch" };
	}
	const sessionId = sessionIdOf(req);
	if (sessionId === undefined) {
		return { ok: false, status: 403, reason: "reauthentication_required" };
	}

	// A session that authenticated at or before the sessions boundary may not mint a
	// consent dated after it; `authTime` never changes, so signing in again is the
	// remedy, and the distinct error lets the page say so.
	const session = await admittedSession(admission, claim, action);
	if (isAdmissionOutage(session)) {
		return { ok: false, status: 503, reason: "unavailable", admissionStore: session.unavailable };
	}
	if (session === null) return { ok: false, status: 403, reason: "reauthentication_required" };

	// Which question is being asked, so that a failure names what could not answer.
	let asking: Omit<Unanswered, "error"> = { store: "federation_grant", step: "is_current_intent" };
	try {
		if (!(await options.grantStore.isCurrentIntent(intent.grantId, intent.handle, now()))) {
			return { ok: false, status: 400, reason: "stale" };
		}
		asking = { store: "client", step: "find" };
		const client = await options.clientRepository.findById(intent.clientId);
		// Read as a list or as nothing (`federationGrantAllowlist`): a repository
		// answering a string would otherwise match by substring.
		const allowed = federationGrantAllowlist(
			(client as { allowedFederationGrantConnections?: unknown } | null)
				?.allowedFederationGrantConnections,
		);
		if (client === null || !allowed.includes(intent.connection)) {
			return { ok: false, status: 403, reason: "connection_not_permitted" };
		}
	} catch (error) {
		// Fails closed: a pointer or a client that cannot be read is not a yes.
		return { ok: false, status: 503, reason: "unavailable", unanswered: { ...asking, error } };
	}

	const connection = options.connections.get(intent.connection);
	if (
		connection === undefined ||
		// The revisions pin the issuer and client, not the federation's name; boot
		// probed the Store under the name the connection has NOW.
		connection.federation !== intent.federation ||
		federationGrantIdentityRevision(connection) !== intent.identityRevision ||
		federationGrantAuthorizationRevision(connection) !== intent.authorizationRevision ||
		connection.callbackUri !== intent.callbackUri
	) {
		// The user would be shown one thing and the upstream asked for another.
		return { ok: false, status: 400, reason: "connection_changed" };
	}
	return { ok: true, binding: { sessionId, sid: session.sid, subject: session.sub } };
}

/**
 * A judgement that could not be made, as one line: the client registry as
 * core's `client_repository_unavailable` with this route as its site, any
 * other store as the route's own outage.
 */
export const judgementUnavailable = (
	log: FederationGrantLog,
	route: "connect" | "consent",
	fields: Readonly<Record<string, string | undefined>>,
	intent: FederationGrantIntent,
	unanswered: Unanswered,
): void => {
	if (unanswered.store === "client") {
		log.clientRepositoryUnavailable(`federation_grant_${route}`, intent.clientId, unanswered.error);
		return;
	}
	log.outage(
		`federation_grant_${route}_unavailable`,
		{ ...fields, reason: "storage", store: unanswered.store, step: unanswered.step },
		unanswered.error,
	);
};

/**
 * Check 3, asked before the exchange and again before activation with the same
 * claim: the same express session and durable session the flow started in,
 * admitted as the callback. An outage is `"unavailable"`, already logged by
 * admission.
 */
export async function sessionHolds(
	admission: AdmissionDeps,
	req: Request,
	claim: SessionClaim,
	transaction: FederationGrantConnectTransaction,
): Promise<"ok" | "reauthentication_required" | "account_mismatch" | "unavailable"> {
	const { binding, intent } = transaction;
	if (!claim.authenticated) return "reauthentication_required";
	if (claim.subject !== intent.subject || binding.subject !== intent.subject) {
		return "account_mismatch";
	}
	if (sessionIdOf(req) !== binding.sessionId || claim.sid !== binding.sid) {
		return "reauthentication_required";
	}
	const session = await admittedSession(admission, claim, CALLBACK);
	if (isAdmissionOutage(session)) return "unavailable";
	return session === null ? "reauthentication_required" : "ok";
}
