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
 * `GET /connect`: the lodged intent read by its handle, a browser that is not
 * signed in sent to login, the judgement as `federation_grants.connect`, and the
 * consent question parked for this browser's binding before the browser is sent
 * to the consent page. Connect never approves or creates an upstream transaction.
 * An unknown handle, every refusal and every `503` this handler answers is audited
 * as `federation.grant.authorization_failed`, with only what is established by then.
 */

import type { FederationGrantIntent, FederationGrantIntentStore } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import { plain } from "./browserAnswers.mjs";
import type { BrowserFlow } from "./browserFlow.mjs";
import { CONNECT, type Judgement, judge, judgementUnavailable } from "./browserJudgement.mjs";
import { claimOf, isPrefetch, single } from "./browserRequest.mjs";
import { federationGrantConnectUri } from "./lodgeRoute.mjs";
import { requestIdOf } from "./requestId.mjs";

export function createConnectHandler({
	options,
	now,
	randomId,
	log,
	admissionFor,
	failed,
}: BrowserFlow): RequestHandler {
	return async (req, res) => {
		try {
			// A prefetch is not the user asking: nothing is parked for it.
			if (isPrefetch(req)) {
				res.status(204).end();
				return;
			}
			const handle = single(req.query.request);
			if (handle === undefined) {
				plain(res, 400, "This link is not valid.");
				return;
			}
			let intent: FederationGrantIntent | null;
			try {
				intent = await options.intentStore.getIntent(handle, now());
			} catch (error) {
				log.outage(
					"federation_grant_connect_unavailable",
					{
						correlationId: requestIdOf(res),
						reason: "storage",
						store: "federation_grant_intent",
						step: "get_intent",
					},
					error,
				);
				failed(req, res, "unavailable");
				plain(res, 503, "Temporarily unavailable.");
				return;
			}
			if (intent === null) {
				failed(req, res, "stale");
				plain(res, 400, "This link has expired or has already been used. Start again.");
				return;
			}
			// Not signed in: sign in and come back to exactly this link (its handle only).
			// Read from the claim before the session is asked anything, as `/authorize` does.
			const claim = claimOf(req);
			if (!claim.authenticated) {
				res.redirect(303, options.login.urlFor(federationGrantConnectUri(options.issuer, handle)));
				return;
			}
			const judged = await judge(
				options,
				admissionFor({ grantId: intent.grantId, correlationId: requestIdOf(res) }),
				req,
				claim,
				CONNECT,
				intent,
				now,
			);
			if (!judged.ok) {
				if (judged.reason === "unavailable" && judged.unanswered !== undefined) {
					judgementUnavailable(
						log,
						"connect",
						{ grantId: intent.grantId, correlationId: requestIdOf(res) },
						intent,
						judged.unanswered,
					);
				}
				failed(req, res, judged.reason, intent);
				plain(res, judged.status, messageFor(judged.reason));
				return;
			}
			let parked: Awaited<ReturnType<FederationGrantIntentStore["parkConsent"]>>;
			try {
				parked = await options.intentStore.parkConsent({
					handle,
					challenge: randomId(),
					binding: judged.binding,
					now: now(),
				});
			} catch (error) {
				log.outage(
					"federation_grant_connect_unavailable",
					{
						grantId: intent.grantId,
						correlationId: requestIdOf(res),
						reason: "storage",
						store: "federation_grant_intent",
						step: "park_consent",
					},
					error,
				);
				failed(req, res, "unavailable", intent);
				plain(res, 503, "Temporarily unavailable.");
				return;
			}
			if (parked === null) {
				// Parked for another browser, or no longer live: the store does not say
				// which, so the audit carries the one outcome the answer gives both.
				failed(req, res, "stale", intent);
				plain(res, 400, "This link has expired or has already been used. Start again.");
				return;
			}
			res.redirect(303, consentLocation(options.consentUrl, options.issuer, parked.challenge));
		} catch (error) {
			log.unexpected("connect", { correlationId: requestIdOf(res) }, error);
			plain(res, 500, "Something went wrong.");
		}
	};
}

/** The consent page's URL with the challenge on it. */
function consentLocation(consentUrl: string, issuer: string, challenge: string): string {
	const url = new URL(consentUrl, issuer);
	url.searchParams.set("challenge", challenge);
	// Always absolute on the issuer: a normalised path would turn
	// `/.//evil.example/consent` into a protocol-relative `//evil.example/consent`
	// Location carrying the challenge to another host. Boot refuses such a path too.
	return url.href;
}

function messageFor(reason: Exclude<Judgement, { ok: true }>["reason"]): string {
	switch (reason) {
		case "subject_mismatch":
			return "This request was made for another account.";
		case "reauthentication_required":
			return "Sign in again to continue.";
		case "stale":
			return "This request was replaced by a newer one. Start again.";
		case "connection_not_permitted":
			return "This application may no longer use this connection.";
		case "connection_changed":
			return "The connection has changed since this request was made. Start again.";
		case "unavailable":
			return "Temporarily unavailable.";
	}
}
