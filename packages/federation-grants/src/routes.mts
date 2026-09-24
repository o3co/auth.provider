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
 *   3. content type and body parsing, and right after them the answer to
 *      what the parsers reject (`parserRefusals`);
 *   4. client authentication;
 *   5. the handlers;
 *   6. everything this package does not serve, as a 404;
 *   7. the last error handler, for what escaped every handler: a logged 500
 *      (`unexpectedErrors`).
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
	consoleLogger,
	createRateLimitGuard,
	type Logger,
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
import {
	createSanitizedAuditSink,
	createSanitizedLogger,
	isInstance,
	readField,
	unexpectedErrorFields,
} from "./report.mjs";
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
 * Express's own refusal of a path parameter it could not percent-decode —
 * `/oauth/federation-grants/%zz/revoke`. Express 5 raises a `URIError` with
 * `status = 400` and no `expose`, at whichever layer first matches the
 * parameter: the denial audit ahead of the throttle for `token` and
 * `revoke`, the route itself for `status`. The request's own mistake.
 */
export const undecodablePath = (error: unknown): boolean =>
	isInstance(error, URIError) && readField(error, "status") === 400;

/**
 * A refusal that is the caller's mistake, as the answer it gets.
 *
 * body-parser raises `http-errors`: `expose: true` with a 4xx `status` for
 * everything the request got wrong — a body over the limit or with more
 * parameters than it takes (`413 body_too_large`), a charset or
 * `Content-Encoding` it cannot decode (`415 unsupported_encoding`), JSON it
 * cannot read or a compressed body that does not decompress (`400
 * malformed_body`). A path parameter Express could not decode is `400
 * malformed_path` (`undecodablePath`). Answered as a 500 instead, any caller
 * could produce server errors at will. `null` for anything else. Shared by
 * both routers, and only ever applied where these are the errors that can
 * arrive (`parserRefusals`).
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
 * The parsers' refusals, answered in this package's own vocabulary — mounted
 * directly after the parsers, so the errors it sees are theirs and those of
 * the middleware ahead of them. Nothing of the parser's error reaches the
 * caller: `body-parser` puts the offending input into its message for a JSON
 * syntax error, so only `expose`, `status` and `type` are read. Anything
 * `parserRefusal` does not recognise passes on to `unexpectedErrors`.
 *
 * Mounted last instead, it read an `expose`d 4xx from anywhere — a store, a
 * handler — as a refused body.
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
 * The routers' last error handler. An error that reaches it has escaped
 * every handler: it is `500 server_error` (`unexpected_error`), a fixed
 * description because whatever is in the error is not the caller's business,
 * and it is logged as `federation_grants_unexpected_error` with
 * `unexpectedErrorFields` — a classification and a status, nothing of the
 * error's text. The one exception is a path parameter Express could not
 * decode at a route itself (`undecodablePath`), which is the caller's `400
 * malformed_path` wherever it surfaces.
 */
export const unexpectedErrors = (logger: Logger | undefined): ErrorRequestHandler => {
	const log = createSanitizedLogger(logger ?? consoleLogger);
	return (error, _req, res, next) => {
		if (res.headersSent) return next(error);
		if (undecodablePath(error)) {
			res.status(400).json({ error: "invalid_request", error_description: "malformed_path" });
			return;
		}
		log.error(unexpectedErrorFields(error), "federation_grants_unexpected_error");
		res.status(500).json({ error: "server_error", error_description: "unexpected_error" });
	};
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
	// only thing auditing one. Each a route (`router.all`) on its own path, not
	// `router.use`, which would match every path beneath it too and audit a
	// 404 at `/:grantId/token/extra` as a token denial.
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
	router.use(parserRefusals);
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
	router.use(unexpectedErrors(options.logger));
	return router;
}
