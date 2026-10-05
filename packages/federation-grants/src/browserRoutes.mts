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
 * The browser half of federation-grant acquisition, mounted at
 * `/session/federation-grants`: the connect start a client sends the user to,
 * the consent the deployment's page reads and answers, and the upstream callback.
 * This file mounts each stage behind the shutdown drain and, when a limiter is
 * wired, the browser budget; what follows holds across the stages.
 *
 * Connect and the callback are navigations: redirects and plain text, never a
 * JSON body. `GET`/`POST /consent` mirror `/oauth/consent` for the page that
 * already implements it: JSON data and errors, `401 login_required`, one
 * indistinguishable answer for any challenge with nothing behind it, and `303`
 * for both `POST` outcomes. None inherits the JSON router's client
 * authentication, 404 or throttle body.
 *
 * Connect is cross-site by construction, so it is not held to the navigation
 * rule the account-link start is (the `csrfGuard`'s `checkNavigation`), and
 * `session.csrf.trustedOrigins` is not widened to client origins; consent is
 * its CSRF defence. The answer is held to the deployment's `csrfGuard`
 * (`check`: this origin, as core's `CsrfGuard` defines it, or a trusted one,
 * or, naming no origin, the guard's double-submit token) and needs the
 * challenge AND the exact session binding. That holds only while connect never approves
 * or creates an upstream transaction, every grant and renewal (first-party
 * clients too) goes through consent, the consent data is never readable
 * cross-origin with credentials, the challenge never reaches another origin
 * via a referrer (`Referrer-Policy: no-referrer` on every response here; the
 * deployment's page keeps its own URL on its origin), and the answer
 * re-admits the session. Making consent skippable is a redesign of this
 * exemption.
 *
 * Whether the session may go on is core's `admitSession` on the cookie's claim,
 * as `federation_grants.connect`, `.consent` and `.callback` (the callback asks
 * twice: before the exchange and before activation). The stages check the
 * flow's own conditions: the intent's subject, the browser binding (express
 * session id and durable `sid`), the grant's current intent, the client's
 * permission, the connection's pins and the grants boundary. Anything admission
 * refuses gets the dead-session answer (connect: plain `403`; consent:
 * `403 reauthentication_required`; callback: `error=reauthentication_required`),
 * except a `step_up` at connect, which is sent once on the requirement's trip
 * (`browserConnect.mts`); an unauthenticated cookie at connect is sent to
 * login instead.
 *
 * Every `503` and every callback `temporarily_unavailable` redirect writes one
 * error line, `federation_grant_{connect,consent,callback}_unavailable`, with
 * `store` and `step` (or `reason`). Admission, the client registry and the
 * throttle log their own outages through core; a failure that changed no answer
 * is one warn.
 */

import {
	checkCanonicalIssuer,
	checkResolver,
	checkWithFailMode,
	createRateLimitPolicy,
	describeIssuerRejection,
} from "@o3co/auth-provider-core";
import express, { type RequestHandler, type Response, type Router } from "express";
import { jsonError, noStoreNoReferrer, plain } from "./browserAnswers.mjs";
import { createCallbackHandler } from "./browserCallback.mjs";
import { createConnectHandler } from "./browserConnect.mjs";
import { createConsentAnswerHandler } from "./browserConsentAnswer.mjs";
import { createBrowserFlow, type FederationGrantBrowserRouterOptions } from "./browserFlow.mjs";
import { CALLBACK, CONNECT, CONSENT } from "./browserJudgement.mjs";
import { createPendingConsentHandler } from "./browserPendingConsent.mjs";
import { createRequestIdMiddleware } from "./requestId.mjs";
import { parserRefusals, unexpectedErrors } from "./routes.mjs";

export type {
	FederationGrantBrowserRouterOptions,
	FederationGrantDelegatedAuthorizer,
} from "./browserFlow.mjs";

/** Where this router is mounted. */
export const FEDERATION_GRANTS_BROWSER_MOUNT_PATH = "/session/federation-grants";

/** The limiter tag; a budget of its own, apart from the JSON routes'. */
export const FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX = "federation_grants_browser";

const BODY_LIMIT = "8kb";

export function createFederationGrantBrowserRouter(
	options: FederationGrantBrowserRouterOptions,
): Router {
	// Refused where the composition is assembled, not answered 500 on every
	// request: a missing resolver, or one the planner did not build.
	const requirements = checkResolver(options.requirements, "createFederationGrantBrowserRouter", [
		CONNECT,
		CONSENT,
		CALLBACK,
	]);
	// Admission reads the sessions boundary only when handed one; without it a
	// session the boundary has ended would be admitted, so a hand-built router
	// without it is refused.
	const subjectRevocation = options.subjectRevocation;
	if (typeof subjectRevocation !== "object" || subjectRevocation === null) {
		throw new TypeError(
			"createFederationGrantBrowserRouter: subjectRevocation is required — the sessions " +
				"boundary a session must have authenticated after is read through it",
		);
	}
	// Likewise the issuer every URL here is built on: one that is not an absolute
	// http(s) URL would make every request a 500.
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection !== null) {
		throw new TypeError(
			`createFederationGrantBrowserRouter: issuer ${describeIssuerRejection(issuerRejection)} — it is oauth.jwt.issuer`,
		);
	}
	const flow = createBrowserFlow(options, requirements, subjectRevocation);
	const router = express.Router();

	// The deployment's own logger and audit sink: a limiter outage here is
	// logged and audited as on every other throttled route.
	const throttlePolicy =
		options.rateLimiter === undefined
			? undefined
			: createRateLimitPolicy(
					{
						limiter: options.rateLimiter,
						tag: FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX,
						...(options.logger === undefined ? {} : { logger: options.logger }),
						...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }),
					},
					"createFederationGrantBrowserRouter",
				);
	/**
	 * The browser budget: the outage policy is core's, the rendering is the
	 * transport's. Without a limiter, a request passes.
	 */
	const throttle =
		(render: (res: Response, status: number) => void): RequestHandler =>
		async (req, res, next) => {
			if (throttlePolicy === undefined) return next();
			const ip = req.ip ?? "unknown";
			const outcome = await checkWithFailMode(
				throttlePolicy,
				`${FEDERATION_GRANTS_BROWSER_RATE_LIMIT_PREFIX}:ip:${ip}`,
				{
					ip,
					...(req.get("user-agent") === undefined ? {} : { userAgent: req.get("user-agent") }),
				},
			);
			if (outcome.status === "unavailable") {
				if (outcome.failMode === "open") return next();
				return render(res, 503);
			}
			if (!outcome.decision.allowed) return render(res, 429);
			next();
		};

	/**
	 * Admits a handler into the shutdown drain, as the JSON routes are: an unadmitted
	 * callback could consume its transaction and then have the grant store closed
	 * under it before the credential is written. Once the drain has begun, new work
	 * is refused before it touches anything.
	 */
	const admitted =
		(render: (res: Response) => void, handler: RequestHandler): RequestHandler =>
		async (req, res, next) => {
			const release = options.background.admit();
			if (release === undefined) {
				render(res);
				return;
			}
			try {
				await handler(req, res, next);
			} finally {
				release();
			}
		};
	const shuttingDownPlain = (res: Response) => plain(res, 503, "Temporarily unavailable.");
	const shuttingDownJson = (res: Response) =>
		jsonError(res, 503, "service_unavailable", "shutting_down");

	router.use(noStoreNoReferrer);
	router.use(createRequestIdMiddleware());

	// --- GET /connect ---------------------------------------------------------
	router.get(
		"/connect",
		throttle((res, status) =>
			plain(res, status, status === 429 ? "Too many requests." : "Temporarily unavailable."),
		),
		admitted(shuttingDownPlain, createConnectHandler(flow)),
	);

	// --- GET / POST /consent -------------------------------------------------
	const consentThrottle = throttle((res, status) =>
		status === 429
			? jsonError(res, 429, "rate_limited", "provider")
			: jsonError(res, 503, "temporarily_unavailable", "rate_limiter"),
	);

	// Admitted like the POST: the read touches the durable session, the intent store
	// and the client registry, which a drain must not close under it.
	router.get(
		"/consent",
		consentThrottle,
		admitted(shuttingDownJson, createPendingConsentHandler(flow)),
	);

	router.post(
		"/consent",
		consentThrottle,
		express.json({ limit: BODY_LIMIT }),
		express.urlencoded({ extended: false, limit: BODY_LIMIT }),
		parserRefusals,
		admitted(shuttingDownJson, createConsentAnswerHandler(flow)),
	);

	// --- GET /callback/:connection -----------------------------------------
	router.get(
		"/callback/:connection",
		throttle((res, status) =>
			plain(res, status, status === 429 ? "Too many requests." : "Temporarily unavailable."),
		),
		admitted(shuttingDownPlain, createCallbackHandler(flow)),
	);

	// Everything else under the mount: plain, not the JSON router's 404.
	router.use((_req, res) => plain(res, 404, "Not found."));
	router.use(unexpectedErrors(options.logger, "federation_grants_browser"));
	return router;
}
