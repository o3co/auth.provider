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
 * The consent question parked for this browser: the one reader behind `GET` and
 * `POST /consent`, so the page learns nothing on `GET` that the answer would then
 * refuse, and `GET /consent`'s data. A challenge with nothing behind it for this
 * browser, whatever the reason, gets the one indistinguishable answer. Every
 * `503` it answers is audited as `federation.grant.authorization_failed` with the
 * outcome `unavailable`, naming the flow only once its intent has been read.
 */

import {
	type ClientRepository,
	describeAdmissionOutage,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { jsonError, NO_PENDING } from "./browserAnswers.mjs";
import type { BrowserFlow } from "./browserFlow.mjs";
import { CONSENT, judge, judgementUnavailable } from "./browserJudgement.mjs";
import { claimOf, sessionIdOf, single } from "./browserRequest.mjs";
import { requestIdOf } from "./requestId.mjs";

/**
 * The parked question, if this browser may see it — or `null` after an
 * answer has been sent. One reader for both methods, so that the page can
 * learn nothing on GET that the POST would then refuse.
 */
export const pendingFor = async (
	{ options, now, log, admissionFor, failed }: BrowserFlow,
	req: Request,
	res: Response,
	challenge: unknown,
) => {
	const claim = claimOf(req);
	if (!claim.authenticated) {
		jsonError(res, 401, "login_required", "no authenticated session");
		return null;
	}
	const presented = single(challenge);
	if (presented === undefined) {
		jsonError(res, 400, "invalid_request", "challenge is required");
		return null;
	}
	let consent: Awaited<ReturnType<FederationGrantIntentStore["getConsent"]>>;
	let intent: FederationGrantIntent | null = null;
	let step = "get_consent";
	try {
		consent = await options.intentStore.getConsent(presented, now());
		step = "get_intent";
		if (consent !== null) intent = await options.intentStore.getIntent(consent.intentHandle, now());
	} catch (error) {
		log.outage(
			"federation_grant_consent_unavailable",
			{
				method: req.method,
				correlationId: requestIdOf(res),
				reason: "storage",
				store: "federation_grant_intent",
				step,
			},
			error,
		);
		// Nothing read names a flow yet: the audit carries this request alone.
		failed(req, res, "unavailable");
		jsonError(res, 503, "temporarily_unavailable", "storage");
		return null;
	}
	const binding = consent?.binding;
	// Another browser's challenge reads exactly as no challenge at all.
	if (
		consent === null ||
		intent === null ||
		binding === undefined ||
		binding.sessionId !== sessionIdOf(req) ||
		binding.sid !== claim.sid ||
		binding.subject !== claim.subject
	) {
		jsonError(res, 400, "invalid_request", NO_PENDING);
		return null;
	}
	const judged = await judge(
		options,
		admissionFor({
			method: req.method,
			grantId: intent.grantId,
			correlationId: requestIdOf(res),
		}),
		req,
		claim,
		CONSENT,
		intent,
		now,
	);
	if (!judged.ok) {
		if (judged.reason === "unavailable" && judged.unanswered !== undefined) {
			judgementUnavailable(
				log,
				"consent",
				{ method: req.method, grantId: intent.grantId, correlationId: requestIdOf(res) },
				intent,
				judged.unanswered,
			);
		}
		failed(req, res, judged.reason, intent);
		if (judged.reason === "reauthentication_required") {
			jsonError(res, 403, "reauthentication_required", "sign in again to continue");
		} else if (judged.reason === "unavailable") {
			// The description names what failed: the client registry as the GET's own lookup
			// does, the session's part by core's `describeAdmissionOutage`, the route's own
			// stores as `storage`.
			jsonError(
				res,
				503,
				"temporarily_unavailable",
				judged.admissionStore !== undefined
					? describeAdmissionOutage(judged.admissionStore)
					: judged.unanswered?.store === "client"
						? "client registry unavailable"
						: "storage",
			);
		} else if (judged.reason === "connection_not_permitted") {
			jsonError(res, 403, "access_denied", "connection_not_permitted");
		} else {
			// Stale, changed, or another subject's: nothing here to answer.
			jsonError(res, 400, "invalid_request", NO_PENDING);
		}
		return null;
	}
	return { consent, intent, binding: judged.binding, challenge: presented };
};

/** `GET /consent`: what the page shows the user, as data. */
export function createPendingConsentHandler(flow: BrowserFlow): RequestHandler {
	const { options, now, log } = flow;
	return async (req, res) => {
		try {
			const found = await pendingFor(flow, req, res, req.query.challenge);
			if (found === null) return;
			const { consent, intent } = found;
			let client: Awaited<ReturnType<ClientRepository["findById"]>>;
			try {
				client = await options.clientRepository.findById(intent.clientId);
			} catch (error) {
				log.clientRepositoryUnavailable("federation_grant_consent", intent.clientId, error);
				jsonError(res, 503, "temporarily_unavailable", "client registry unavailable");
				return;
			}
			const described = client as { clientName?: string; clientUri?: string } | null;
			res.status(200).json({
				challenge: consent.challenge,
				client_id: intent.clientId,
				...(described?.clientName === undefined ? {} : { client_name: described.clientName }),
				...(described?.clientUri === undefined ? {} : { client_uri: described.clientUri }),
				connection: intent.connection,
				scopes: [...consent.scopes],
				...(intent.resource === undefined ? {} : { resource: intent.resource }),
				// The grant's duration, counted from the answer; an absolute date computed now
				// would be an estimate the grant does not keep.
				grant_expires_in: Math.floor(consent.lifetimeMs / 1000),
				// What the page must tell the user, as data.
				continues_after_logout: true,
				expires_in: Math.max(0, Math.floor((consent.expiresAt.getTime() - now().getTime()) / 1000)),
			});
		} catch (error) {
			log.unexpected("consent", { method: req.method, correlationId: requestIdOf(res) }, error);
			jsonError(res, 500, "server_error", "unexpected_error");
		}
	};
}
