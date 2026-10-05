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
 * The router for this package's client-authenticated routes, and the order its
 * middleware runs in, which is the security property. See ADR
 * 2026-09-17-federation-grants-offline-delegation, D9.
 *
 *   1. cache directives and correlation, ahead of anything that can answer;
 *   2. when a limiter is wired, the throttle, keyed on the IP, BEFORE client
 *      authentication, so that repeated unauthenticated hits are bounded
 *      before a repository lookup;
 *   3. content type and body parsing, then `parserRefusals`;
 *   4. client authentication, before domain validation, so an unauthenticated
 *      caller learns nothing about a grant, not even from a refusal's timing;
 *   5. the handlers;
 *   6. everything this package does not serve, as a 404;
 *   7. `unexpectedErrors`, a logged 500 for what escaped every handler.
 *
 * Client authentication's lines carry `site: "federation_grants"`. Exported so
 * a composition root that mounts the handlers itself gets the same chain.
 */

import {
	type ClientRepository,
	checkCanonicalIssuer,
	consoleLogger,
	createRateLimitGuard,
	describeIssuerRejection,
	type Logger,
	type RateLimiter,
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
import { createFederationGrantLog, isInstance, readField } from "./log.mjs";
import { createRequestIdMiddleware, requestIdOf } from "./requestId.mjs";
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
 * The body limit, checked from `Content-Length` ahead of the parsers, so a
 * declared oversized body is refused unread and the bound holds even if
 * another module's parser under `/oauth` runs first (`body-parser` does not
 * parse a body twice, so the `limit` below would be skipped). See README,
 * "Beside `oauthModule`".
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
 * package does not serve. The body carries no description: it names no
 * feature to an unauthenticated caller.
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

/**
 * A 404 under the mount path that names no feature, for a composition root
 * that mounts the path itself while the feature is off; the module mounts
 * nothing then.
 */
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
 * Express's own refusal of a path parameter it could not percent-decode —
 * `/oauth/federation-grants/%zz/revoke`. Express 5 raises a `URIError` with
 * `status = 400` and no `expose`, at whichever layer first matches the
 * parameter: the denial audit ahead of the throttle for `token` and
 * `revoke`, the route itself for `status`. The request's own mistake.
 */
export const undecodablePath = (error: unknown): boolean =>
	isInstance(error, URIError) && readField(error, "status") === 400;

/**
 * A refusal that is the caller's mistake, as the answer it gets; `null` for
 * anything else. Answered as a 500, any caller could produce server errors at
 * will. It recognises body-parser's `http-errors` (`expose` with a 4xx
 * `status`, then `type`) and an undecodable path, and is only applied where
 * these are the errors that can arrive (`parserRefusals`). See README,
 * "Beside `oauthModule`".
 */
export const parserRefusal = (
	error: unknown,
): { readonly status: 400 | 413 | 415; readonly description: string } | null => {
	if (undecodablePath(error)) return { status: 400, description: "malformed_path" };
	// Every read guarded (`readField`): a getter that throws here would make
	// the error handler itself throw.
	const expose = readField(error, "expose");
	const status = readField(error, "status");
	const type = readField(error, "type");
	if (expose !== true || typeof status !== "number" || status < 400 || status >= 500) return null;
	if (type === "entity.too.large" || type === "parameters.too.many") {
		return { status: 413, description: "body_too_large" };
	}
	if (type === "charset.unsupported" || type === "encoding.unsupported") {
		return { status: 415, description: "unsupported_encoding" };
	}
	return { status: 400, description: "malformed_body" };
};

/**
 * The parsers' refusals, in this package's own vocabulary. Mounted directly
 * after the parsers, so the errors it sees are theirs and those of the
 * middleware ahead of them; mounted last, it would read an `expose`d 4xx from
 * a store or a handler as a refused body. Nothing of the parser's error
 * reaches the caller: `body-parser` puts the offending input into its message
 * for a JSON syntax error, so only `expose`, `status` and `type` are read.
 */
export const parserRefusals: ErrorRequestHandler = (error, _req, res, next) => {
	const refusal = res.headersSent ? null : parserRefusal(error);
	if (refusal === null) return next(error);
	res.status(refusal.status).json({
		error: "invalid_request",
		error_description: refusal.description,
	});
};

/**
 * The routers' last error handler, for an error that escaped every handler: a
 * fixed `500 server_error` (`unexpected_error`), since what is in the error is
 * not the caller's business, logged as `federation_grants_unexpected_error`
 * with `site` (the router it escaped), the request's `correlationId` and the
 * error's projection. An undecodable path parameter (`undecodablePath`) is the
 * caller's `400 malformed_path` wherever it surfaces.
 */
export const unexpectedErrors = (
	logger: Logger | undefined,
	site: "federation_grants" | "federation_grants_browser",
): ErrorRequestHandler => {
	const log = createFederationGrantLog(logger);
	return (error, _req, res, next) => {
		if (res.headersSent) return next(error);
		if (undecodablePath(error)) {
			res.status(400).json({ error: "invalid_request", error_description: "malformed_path" });
			return;
		}
		log.unexpected(site, { correlationId: requestIdOf(res) }, error);
		res.status(500).json({ error: "server_error", error_description: "unexpected_error" });
	};
};

export interface FederationGrantRouterOptions extends FederationGrantTokenHandlerOptions {
	/**
	 * What creating a grant needs. Absent, the two lodging routes are
	 * not mounted and answer as any unknown path does; the module always passes
	 * it, having refused at boot a deployment that could not supply it.
	 */
	readonly acquisition?: FederationGrantAcquisitionRouteOptions;
	readonly clientRepository: ClientRepository;
	/**
	 * `oauth.jwt.issuer`, held to core's `checkCanonicalIssuer`: the Basic
	 * realm, the audience an assertion may name, and what a lodging's
	 * `connect_uri` is built on.
	 */
	readonly issuer: string;
	/**
	 * The routes' budget; its own `failMode` is the outage policy. Absent, the
	 * routes are not throttled.
	 */
	readonly rateLimiter?: RateLimiter;
	/** Where a `private_key_jwt` assertion's single-use `jti` is recorded. */
	readonly replaySeenSet?: ReplaySeenSet;
}

export function createFederationGrantRouter(options: FederationGrantRouterOptions): Router {
	// Refused where the composition is assembled: a lodging builds its
	// `connect_uri` on the issuer, and on one that is not an absolute http(s)
	// URL — `mailto:`, `urn:` — that throws, a 500 on every request. Core's
	// canonical rule, the one `oauth.jwt.issuer` is held to.
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection !== null) {
		throw new TypeError(
			`createFederationGrantRouter: issuer ${describeIssuerRejection(issuerRejection)} — it is oauth.jwt.issuer`,
		);
	}
	const router = express.Router();
	router.use(transport());
	// Before the throttle and before authentication, because what it watches
	// for is a response those two write themselves: the handler is not the only
	// thing that can refuse a token request. Each a route (`router.all`) on its
	// own path, not `router.use`, which would match every path beneath it too
	// and audit a 404 at `/:grantId/token/extra` as a token denial.
	for (const operation of ["token", "revoke"] as const) {
		router.all(
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
		// `all` on the exact paths, not `use`: `use("/")` would match every path
		// under the mount and count a token refusal as a lodging one, and
		// `use("/:grantId/reauthorize")` every path beneath the reauthorize route.
		router.all("/", requestDenials);
		router.all("/:grantId/reauthorize", requestDenials);
	}
	// Ahead of client authentication, as the token endpoint orders it: repeated
	// unauthenticated hits are bounded before they reach a repository lookup.
	// `deniedDescription` keeps this route's throttle speaking the same
	// vocabulary as core's — `rate_limited` with the reason `provider` — rather
	// than whichever budget name the limiter adapter reports.
	if (options.rateLimiter !== undefined) {
		router.use(
			createRateLimitGuard({
				limiter: options.rateLimiter,
				tag: FEDERATION_GRANTS_RATE_LIMIT_PREFIX,
				deniedDescription: "provider",
				...(options.logger === undefined ? {} : { logger: options.logger }),
				...(options.auditSink === undefined ? {} : { auditSink: options.auditSink }),
			}),
		);
	}
	router.use(supportedContentType);
	router.use(withinBodyLimit);
	router.use(express.json({ limit: BODY_LIMIT }));
	router.use(express.urlencoded({ extended: false, limit: BODY_LIMIT }));
	router.use(parserRefusals);
	router.use(
		createClientAuthMiddleware(options.clientRepository, {
			issuer: options.issuer,
			// `allowPublicClients` omitted: a public client is identified by a
			// value that is not a secret, and nothing else here proves it is the
			// client it says it is.
			...(options.replaySeenSet === undefined ? {} : { replaySeenSet: options.replaySeenSet }),
			// Its `client_repository_unavailable` and `client_assertion_refused`
			// lines, with the site that tells them from the token endpoint's.
			logger: (options.logger ?? consoleLogger).child({ site: "federation_grants" }),
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
	router.use(unexpectedErrors(options.logger, "federation_grants"));
	return router;
}
