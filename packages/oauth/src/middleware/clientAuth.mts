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

import {
	type ClientRepository,
	consoleLogger,
	isWellFormedClientId,
	type Logger,
	logClientRepositoryUnavailable,
	type PublicClient,
	type ReplaySeenSet,
	sanitizeErrorText,
	type TokenEndpointAuthMethod,
} from "@o3co/auth-provider-core";
import type { RequestHandler, Response } from "express";
import { createClientAssertionVerifier, hasClientAssertion } from "./clientAssertion.mjs";

// Exposes `req.oauthClient` to consumers composing this middleware onto their
// own routes. The global Express namespace is the augmentation target that
// works for Express v4 and v5 under pnpm.
declare global {
	namespace Express {
		interface Request {
			/**
			 * The authenticated OAuth client, set by {@link createClientAuthMiddleware}
			 * after successful RFC 6749 §2.3.1 client authentication. Absent when the
			 * request has not been through client-auth middleware.
			 */
			oauthClient?: PublicClient;
		}
	}
}

export interface ClientAuthMiddlewareOptions {
	/**
	 * Issuer URL used to populate the `realm` parameter of `WWW-Authenticate:
	 * Basic` headers per RFC 7235 §2.2. Defaults to `"oauth"` when unset so the
	 * header still carries a syntactically valid realm.
	 */
	issuer?: string;
	/**
	 * Structured logger for repository-failure traces. Defaults to
	 * `consoleLogger` so existing callers compile unchanged.
	 */
	logger?: Logger;
	/**
	 * Whether `tokenEndpointAuthMethod: "none"` clients are accepted. Only
	 * `/oauth/token` may set this (PKCE S256 at `/authorize` is its
	 * authenticity gate): RFC 7662 §2.1 requires introspection callers to be
	 * authenticated, and a client_id is not a secret. Default `false`.
	 */
	allowPublicClients?: boolean;
	/**
	/**
	 * The `jti` single-use record for `private_key_jwt` assertions. Without it
	 * an assertion request is answered `server_error`: a jti that cannot be
	 * recorded could be replayed, so the path fails closed.
	 */
	replaySeenSet?: ReplaySeenSet;
	/**
	 * The absolute token endpoint URL, accepted as an assertion `aud`
	 * alongside `issuer` (RFC 7523 §3). Defaults to `<issuer>/oauth/token`.
	 */
	tokenEndpoint?: string;
	/** The fetch used for a client's `jwksUri`. A proxy, or a test seam. */
	fetch?: typeof fetch;
}

// URI-safe characters per RFC 3986 (plus the few sub-delims commonly seen in
// absolute URIs). Deliberately excludes `"` and `\`, which RFC 7235 §2.2 +
// RFC 7230 quoted-string rules require to be backslash-escaped, and CTL bytes,
// which are forbidden outright.
const SAFE_REALM_CHARS = /^[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$/;

/**
 * The `realm` for a `WWW-Authenticate: Basic` challenge. Every emission site
 * must use it: an unfiltered value could close the quoted-string and inject
 * auth-params, so a value outside {@link SAFE_REALM_CHARS} becomes `"oauth"`.
 * Pass the configured issuer, never a request-derived value such as Host.
 */
export function resolveRealm(issuer: string | undefined): string {
	return issuer && issuer.length > 0 && SAFE_REALM_CHARS.test(issuer) ? issuer : "oauth";
}

/**
 * Decodes an `application/x-www-form-urlencoded`-encoded string per RFC 6749 §2.3.1.
 * `+` is a synonym for space in x-www-form-urlencoded encoding (distinct from %20).
 * `decodeURIComponent` alone does NOT handle `+`, so we normalise it first.
 */
function formUrlDecode(s: string): string {
	return decodeURIComponent(s.replace(/\+/g, " "));
}

interface BasicCreds {
	clientId: string;
	clientSecret: string;
}

type BasicParseResult =
	| { kind: "absent" }
	| { kind: "malformed" }
	| { kind: "ok"; creds: BasicCreds };

function parseBasicAuthHeader(authHeader: string | undefined): BasicParseResult {
	if (typeof authHeader !== "string" || !/^basic\s+/i.test(authHeader)) {
		return { kind: "absent" };
	}
	try {
		const decoded = Buffer.from(authHeader.replace(/^basic\s+/i, ""), "base64").toString("utf8");
		const idx = decoded.indexOf(":");
		if (idx < 0) {
			return { kind: "malformed" };
		}
		const clientId = formUrlDecode(decoded.slice(0, idx));
		const clientSecret = formUrlDecode(decoded.slice(idx + 1));
		return { kind: "ok", creds: { clientId, clientSecret } };
	} catch {
		// decodeURIComponent threw — malformed percent-encoding
		return { kind: "malformed" };
	}
}

/**
 * RFC 6749 §2.3.1 client-authentication middleware for `/oauth/token`,
 * `/oauth/introspect` and `/oauth/revoke`. On success sets `req.oauthClient`
 * and calls `next()`; on failure answers `invalid_client` (RFC 6749 §5.2).
 *
 * - The client's configured `tokenEndpointAuthMethod` is authoritative: a
 *   valid credential sent over another transport is refused.
 * - Basic and body credentials that disagree are refused, so one identity
 *   cannot be pinned in the header and another in the body.
 * - `WWW-Authenticate: Basic` is sent only when the failed attempt was Basic
 *   or no credentials were sent, never to steer other callers to Basic.
 * - A repository that throws is an outage, `503 temporarily_unavailable`, not
 *   `invalid_client` (which a client reads as a bad secret). A malformed
 *   `client_id` (control characters, over-long) is refused as unknown before
 *   the repository is asked, so a client cannot provoke that outage.
 */
export function createClientAuthMiddleware(
	clientRepository: ClientRepository,
	loggerOrOptions: Logger | ClientAuthMiddlewareOptions = {},
): RequestHandler {
	// Also accepts a bare Logger, as older call sites pass; the options object
	// is needed to supply `issuer`.
	const opts: ClientAuthMiddlewareOptions =
		typeof loggerOrOptions === "object" && "warn" in loggerOrOptions
			? { logger: loggerOrOptions as Logger }
			: (loggerOrOptions as ClientAuthMiddlewareOptions);
	const logger: Logger = opts.logger ?? consoleLogger;
	// `resolveRealm` sanitises the issuer. Shared with the sender-constrained
	// reject path in `routes.mts` so the two emission sites cannot drift.
	const wwwAuth = `Basic realm="${resolveRealm(opts.issuer)}"`;
	const allowPublicClients = opts.allowPublicClients === true;
	// `private_key_jwt`: the verifier owns the trust decision; this middleware
	// decides how to answer it and that no second method rides along.
	const assertionVerifier = createClientAssertionVerifier({
		issuer: opts.issuer,
		tokenEndpoint: opts.tokenEndpoint ?? (opts.issuer ? `${opts.issuer}/oauth/token` : undefined),
		replaySeenSet: opts.replaySeenSet,
		logger,
		fetch: opts.fetch,
	});

	// Every refusal goes through these. Descriptions — including the assertion
	// verifier's, which can quote a configured method — are held to RFC 6749
	// §5.2's character set here rather than at each call site.
	function errorBody(error: string, errorDescription?: string) {
		const body: { error: string; error_description?: string } = { error };
		if (errorDescription !== undefined)
			body.error_description = sanitizeErrorText(errorDescription);
		return body;
	}

	function rejectBasic(res: Response, status: number, errorDescription?: string): void {
		res.set("WWW-Authenticate", wwwAuth);
		res.status(status).json(errorBody("invalid_client", errorDescription));
	}

	function rejectPlain(res: Response, status: number, errorDescription?: string): void {
		res.status(status).json(errorBody("invalid_client", errorDescription));
	}
	function rejectAs(res: Response, status: number, error: string, errorDescription?: string): void {
		res.status(status).json(errorBody(error, errorDescription));
	}
	// The repository did not answer: refused as the server's outage, never as
	// a failed authentication (see the JSDoc above).
	function repositoryUnavailable(
		res: Response,
		step: "find" | "authenticate",
		clientId: string,
		cause: unknown,
	): void {
		logClientRepositoryUnavailable(logger, { step, clientId }, cause);
		rejectAs(res, 503, "temporarily_unavailable", "client repository unavailable");
	}

	return async (req, res, next) => {
		const basic = parseBasicAuthHeader(req.headers.authorization);

		if (basic.kind === "malformed") {
			rejectBasic(res, 401, "Malformed client credentials");
			return;
		}

		// RFC 7617 §2: an empty Basic secret is malformed. Refused at the parser
		// so a misconfigured custom repository never sees an "empty == empty"
		// comparison.
		if (basic.kind === "ok" && basic.creds.clientSecret.length === 0) {
			rejectBasic(res, 401, "Malformed client credentials");
			return;
		}

		const body = req.body as Record<string, unknown> | undefined;
		const bodyClientId = typeof body?.client_id === "string" ? body.client_id : undefined;
		const bodyClientSecret =
			typeof body?.client_secret === "string" && body.client_secret.length > 0
				? body.client_secret
				: undefined;

		// A client assertion is its own method, and RFC 6749 §2.3 allows one per
		// request: an assertion beside Basic or a body secret is refused before
		// either is examined, since the combination pins an identity where the
		// other check does not look.
		if (hasClientAssertion(body)) {
			// Presence, not validity: `client_secret=` with an empty value is
			// still a second method on the wire.
			if (basic.kind !== "absent" || body?.client_secret !== undefined) {
				rejectPlain(
					res,
					401,
					"Only one client authentication method per request (RFC 6749 section 2.3): a client_assertion cannot be combined with Basic credentials or client_secret",
				);
				return;
			}
			const outcome = await assertionVerifier.verify(body, (id) => clientRepository.findById(id));
			if (outcome.kind === "ok") {
				req.oauthClient = outcome.client;
				next();
				return;
			}
			if (outcome.kind === "refused") {
				rejectAs(res, outcome.status, outcome.error, outcome.description);
				return;
			}
		}

		// If both Basic and body identify a client they must agree: otherwise one
		// identity could be pinned in a header (less inspected by proxies) and
		// another sent in the body.
		if (
			basic.kind === "ok" &&
			bodyClientId !== undefined &&
			basic.creds.clientId !== bodyClientId
		) {
			rejectBasic(res, 401, "client_id mismatch between Basic header and body");
			return;
		}
		if (
			basic.kind === "ok" &&
			bodyClientSecret !== undefined &&
			basic.creds.clientSecret !== bodyClientSecret
		) {
			rejectBasic(res, 401, "client_secret mismatch between Basic header and body");
			return;
		}

		const clientId = basic.kind === "ok" ? basic.creds.clientId : bodyClientId;
		if (!clientId) {
			// No credentials at all: advertise Basic as a valid retry.
			rejectBasic(res, 401, "Client authentication is required");
			return;
		}

		// A client_id no client can have is answered like an unknown one — and
		// never handed to the repository, which may throw on it (see the JSDoc).
		if (!isWellFormedClientId(clientId)) {
			if (basic.kind === "ok") {
				rejectBasic(res, 401, "Invalid client credentials");
			} else {
				rejectPlain(res, 401, "Unknown client");
			}
			return;
		}

		// The transport the caller used, derived first so a wrong-method request
		// is refused before any secret is checked.
		const usedMethod: TokenEndpointAuthMethod =
			basic.kind === "ok"
				? "client_secret_basic"
				: bodyClientSecret !== undefined
					? "client_secret_post"
					: "none";

		// `findById` first: the configured `tokenEndpointAuthMethod` gates the
		// credential check. For a `none` client it is the final answer.
		let client: PublicClient | null;
		try {
			client = await clientRepository.findById(clientId);
		} catch (err) {
			// Fail-closed: repository unavailability must not grant access — and
			// is not the client's fault either.
			repositoryUnavailable(res, "find", clientId, err);
			return;
		}

		if (!client) {
			if (basic.kind === "ok") {
				rejectBasic(res, 401, "Invalid client credentials");
			} else {
				rejectPlain(res, 401, "Unknown client");
			}
			return;
		}

		// The configured method must match the transport used, even with valid
		// credentials; otherwise the discriminator would be only documentary.
		if (client.tokenEndpointAuthMethod !== usedMethod) {
			const description =
				usedMethod === "none"
					? "Client authentication is required for confidential clients"
					: `tokenEndpointAuthMethod mismatch: client is configured for '${client.tokenEndpointAuthMethod}'`;
			if (basic.kind === "ok") {
				rejectBasic(res, 401, description);
			} else {
				rejectPlain(res, 401, description);
			}
			return;
		}

		if (client.tokenEndpointAuthMethod === "none") {
			// Public-client routes are opt-in: only `/oauth/token` (where PKCE/S256
			// is the authenticity gate enforced at `/authorize`) sets
			// `allowPublicClients: true`. Other routes — `/oauth/introspect` per
			// RFC 7662 §2.1, federation endpoints, etc. — must reject so a known
			// public client_id (a non-secret value) cannot authorize requests.
			if (!allowPublicClients) {
				rejectPlain(res, 401, "Public clients are not allowed on this endpoint");
				return;
			}
			req.oauthClient = client;
			next();
			return;
		}

		// Confidential path: verify the secret. `usedMethod` has already been
		// validated against `client.tokenEndpointAuthMethod`, so we know which
		// source (Basic vs body) supplied the secret.
		const secret =
			usedMethod === "client_secret_basic"
				? // basic.kind === "ok" guaranteed when usedMethod === "client_secret_basic"
					(basic as { kind: "ok"; creds: BasicCreds }).creds.clientSecret
				: bodyClientSecret;
		if (secret === undefined) {
			// Defensive — should not happen because usedMethod selection requires
			// at least one credential source. Surfacing a stable error message
			// keeps the behaviour testable.
			if (basic.kind === "ok") {
				rejectBasic(res, 401, "Client authentication is required");
			} else {
				rejectPlain(res, 401, "Client authentication is required");
			}
			return;
		}

		let authenticated: PublicClient | null;
		try {
			authenticated = await clientRepository.authenticate(clientId, secret);
		} catch (err) {
			repositoryUnavailable(res, "authenticate", clientId, err);
			return;
		}

		if (!authenticated) {
			if (basic.kind === "ok") {
				rejectBasic(res, 401, "Invalid client credentials");
			} else {
				rejectPlain(res, 401, "Invalid client credentials");
			}
			return;
		}

		req.oauthClient = authenticated;
		next();
	};
}
