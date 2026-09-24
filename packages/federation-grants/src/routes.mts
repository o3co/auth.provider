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
 * The router both routes live in, and the order its middleware runs in
 * (#593, D9).
 *
 *   1. cache directives and correlation, ahead of anything that can answer;
 *   2. the throttle, keyed on the IP, BEFORE client authentication, so that
 *      repeated unauthenticated hits are bounded before they reach a
 *      repository lookup;
 *   3. content type and body parsing;
 *   4. client authentication;
 *   5. the handlers;
 *   6. everything this package does not serve, as a 404;
 *   7. a sanitizing error handler, for what the parsers reject.
 *
 * Authentication before domain validation, deliberately: an unauthenticated
 * caller must not be able to learn anything about a grant, including by
 * measuring how long a refusal took.
 *
 * Exported so a composition root that mounts the handlers itself gets the same
 * chain rather than a hand-assembled approximation of it — the ordering above
 * is the security property, not a convenience.
 */

import {
	type ClientRepository,
	createRateLimitGuard,
	type RateLimiter,
	type RateLimitFailMode,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import { createClientAuthMiddleware } from "@o3co/auth-provider-oauth";
import express, { type ErrorRequestHandler, type RequestHandler, type Router } from "express";
import { createRouteDenialAudit } from "./denialAudit.mjs";
import {
	createFederationGrantCreateHandler,
	createFederationGrantReauthorizeHandler,
	type FederationGrantAcquisitionRouteOptions,
} from "./lodgeRoute.mjs";
import { createSanitizedAuditSink, createSanitizedLogger } from "./report.mjs";
import { createRequestIdMiddleware } from "./requestId.mjs";
import { createFederationGrantRevokeHandler } from "./revokeRoute.mjs";
import { createFederationGrantStatusHandler } from "./statusRoute.mjs";
import {
	createFederationGrantTokenHandler,
	type FederationGrantTokenHandlerOptions,
} from "./tokenRoute.mjs";

/** The shared prefix both routes are throttled under: `federation_grants:ip:<ip>`. */
export const FEDERATION_GRANTS_RATE_LIMIT_PREFIX = "federation_grants";

/** At most 16 KiB of body — the same bound the OAuth routes use. */
const BODY_LIMIT = "16kb";
const BODY_LIMIT_BYTES = 16 * 1024;

/**
 * The body limit, restated ahead of the parsers.
 *
 * These routes live under `/oauth`, beside `oauthModule`'s router, which
 * parses the bodies of its own routes only — so in a composition with it,
 * these routes' own parsers are the first to read their bodies, whatever the
 * module order. The bound is still checked from `Content-Length` first: it
 * refuses a declared oversized body before any of it is read, and it holds
 * even if some other module mounts a parser under `/oauth` that runs for
 * every request beneath it (`body-parser` does not parse a body twice, so the
 * `limit` below would then be skipped). A body with no `Content-Length` is
 * bounded by the parsers below.
 */
const withinBodyLimit: RequestHandler = (req, res, next) => {
	const declared = Number(req.headers["content-length"]);
	if (Number.isFinite(declared) && declared > BODY_LIMIT_BYTES) {
		res.status(413).json({ error: "invalid_request", error_description: "body_too_large" });
		return;
	}
	next();
};

/**
 * `Cache-Control` / `Pragma` on every exit, live or refused, ahead of anything
 * that can answer. A 404 with no directives is the shape an intermediary
 * caches heuristically, and a cached "this deployment has no federation
 * grants" would outlive the operator turning them on.
 */
export const noStore: RequestHandler = (_req, res, next) => {
	res.set("Cache-Control", "no-store").set("Pragma", "no-cache");
	next();
};

/**
 * The last handler under the mount path: every method and sub-path this
 * package does not serve.
 *
 * The body carries no description, unlike the neighbouring packages'
 * refusals. That is what a disabled deployment needs:
 * `{"error":"not_found"}` names no feature, so an unauthenticated caller
 * cannot learn that offline delegation is one configuration key away. It is
 * not byte-identical to a deployment without the package installed — there
 * the host's own fallback answers, with its own headers and content type —
 * but nothing in it says what is missing. On an enabled deployment
 * it is the answer for a method that does not exist — and there is no `GET`
 * status alias to point anyone at.
 */
export const notFound: RequestHandler = (_req, res) => {
	res.status(404).json({ error: "not_found" });
};

/** Cache directives then correlation: the two things every exit carries. */
const transport = (): Router => {
	const router = express.Router();
	router.use(noStore);
	router.use(createRequestIdMiddleware());
	return router;
};

/** What a deployment that has not enabled the feature mounts. */
export function createDisabledFederationGrantRouter(): Router {
	const router = express.Router();
	router.use(transport());
	router.use(notFound);
	return router;
}

/**
 * The two media types a body may arrive in.
 *
 * Checked rather than left to the parsers: with neither parser matching, the
 * body would silently be `{}` and the caller would be told `sub is required`
 * for a request whose `sub` they did send. An absent content type is not
 * refused here — a request with no body is a parse failure, which is a more
 * useful answer than an argument about headers.
 */
const supportedContentType: RequestHandler = (req, res, next) => {
	const header = req.headers["content-type"];
	if (header === undefined) return next();
	const media = header.split(";")[0]?.trim().toLowerCase();
	if (media === "application/json" || media === "application/x-www-form-urlencoded") {
		return next();
	}
	res.status(415).json({
		error: "invalid_request",
		error_description: "unsupported_content_type",
	});
};

/**
 * What the body parsers reject, in this package's own vocabulary.
 *
 * Nothing of the parser's error reaches the caller: `body-parser` puts the
 * offending input into its message for a JSON syntax error, so the `type` it
 * classifies with is all that is read.
 */
export const parserErrors: ErrorRequestHandler = (error, _req, res, next) => {
	if (res.headersSent) return next(error);
	const type = (error as { type?: unknown }).type;
	if (type === "entity.too.large") {
		res.status(413).json({ error: "invalid_request", error_description: "body_too_large" });
		return;
	}
	if (type === "entity.parse.failed" || type === "encoding.unsupported") {
		res.status(400).json({ error: "invalid_request", error_description: "malformed_body" });
		return;
	}
	// A composition or programming fault: a fixed description, because whatever
	// is in the error is not the caller's business.
	res.status(500).json({ error: "server_error", error_description: "unexpected_error" });
};

export interface FederationGrantRouterOptions extends FederationGrantTokenHandlerOptions {
	/**
	 * Slice 6: what creating a grant needs. Absent, the two lodging routes are
	 * not mounted and answer as any unknown path does; the module always passes
	 * it, having refused at boot a deployment that could not supply it.
	 */
	readonly acquisition?: FederationGrantAcquisitionRouteOptions;
	readonly clientRepository: ClientRepository;
	/** `oauth.jwt.issuer`: the Basic realm, and the audience an assertion may name. */
	readonly issuer: string;
	readonly rateLimiter: RateLimiter;
	readonly failMode: RateLimitFailMode;
	/** #484: where a `private_key_jwt` assertion's single-use `jti` is recorded. */
	readonly replaySeenSet?: ReplaySeenSet;
}

export function createFederationGrantRouter(options: FederationGrantRouterOptions): Router {
	const router = express.Router();
	router.use(transport());
	// Before the throttle and before authentication, because what it watches
	// for is a response those two write themselves: the handler is not the only
	// thing that can refuse a token request, and until this existed it was the
	// only thing auditing one.
	for (const operation of ["token", "revoke"] as const) {
		router.use(
			`/:grantId/${operation}`,
			createRouteDenialAudit({
				...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
				operation,
				now: options.now ?? (() => new Date()),
				background: options.background,
			}),
		);
	}
	if (options.acquisition !== undefined) {
		const requestDenials = createRouteDenialAudit({
			...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
			operation: "request",
			now: options.now ?? (() => new Date()),
			background: options.background,
		});
		// `all` on the exact collection path, not `use`: `use("/")` would match
		// every path under the mount and count a token refusal as a lodging one.
		router.all("/", requestDenials);
		router.use("/:grantId/reauthorize", requestDenials);
	}
	// Ahead of client authentication, as the token endpoint orders it: repeated
	// unauthenticated hits are bounded before they reach a repository lookup.
	// `deniedDescription` keeps this route's throttle speaking the same
	// vocabulary as core's — `rate_limited` with the reason `provider` — rather
	// than whichever budget name the limiter adapter reports.
	router.use(
		createRateLimitGuard({
			limiter: options.rateLimiter,
			tag: FEDERATION_GRANTS_RATE_LIMIT_PREFIX,
			failMode: options.failMode,
			deniedDescription: "provider",
			...(options.logger === undefined ? {} : { logger: createSanitizedLogger(options.logger) }),
			// Its `rate_limit.unavailable` event carries the limiter's own error
			// message; the same allowlist the logger gets applies to the sink.
			...(options.auditSink === undefined
				? {}
				: { auditSink: createSanitizedAuditSink(options.auditSink) }),
		}),
	);
	router.use(supportedContentType);
	router.use(withinBodyLimit);
	router.use(express.json({ limit: BODY_LIMIT }));
	router.use(express.urlencoded({ extended: false, limit: BODY_LIMIT }));
	router.use(
		createClientAuthMiddleware(options.clientRepository, {
			issuer: options.issuer,
			// `allowPublicClients` omitted: a public client is identified by a
			// value that is not a secret, and nothing else here proves it is the
			// client it says it is.
			...(options.replaySeenSet === undefined ? {} : { replaySeenSet: options.replaySeenSet }),
			...(options.logger === undefined ? {} : { logger: createSanitizedLogger(options.logger) }),
		}),
	);
	router.post("/:grantId/token", createFederationGrantTokenHandler(options));
	router.post("/:grantId/status", createFederationGrantStatusHandler(options));
	router.post("/:grantId/revoke", createFederationGrantRevokeHandler(options));
	if (options.acquisition !== undefined) {
		const lodging = { ...options, acquisition: options.acquisition };
		router.post("/", createFederationGrantCreateHandler(lodging));
		router.post("/:grantId/reauthorize", createFederationGrantReauthorizeHandler(lodging));
	}
	router.use(notFound);
	router.use(parserErrors);
	return router;
}
