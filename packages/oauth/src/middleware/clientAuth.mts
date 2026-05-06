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
	type Logger,
	type PublicClient,
	type TokenEndpointAuthMethod,
} from "@o3co/auth-provider-core";
import type { RequestHandler, Response } from "express";

// Module augmentation: expose `req.oauthClient` for consumers who compose this
// middleware onto their own routes and need the authenticated client downstream.
// Uses the global Express namespace (declared in @types/express-serve-static-core)
// which is the stable, pnpm-friendly augmentation target for both Express v4 and v5.
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

interface ClientAuthMiddlewareOptions {
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
	 * Whether `tokenEndpointAuthMethod === "none"` (public) clients are
	 * accepted on this route. Defaults to `false` because the only routes that
	 * can soundly admit them are `/oauth/token` (where PKCE/S256 is the
	 * authenticity gate, enforced separately at `/oauth/authorize`).
	 *
	 * RFC 7662 §2.1 requires that introspection callers be authenticated;
	 * accepting a public client there would let anyone who knows a client_id
	 * (a non-secret value) query token metadata. Routes other than `/token`
	 * MUST leave this option at the default.
	 */
	allowPublicClients?: boolean;
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
 * Creates RFC 6749 §2.3.1 client-authentication middleware suitable for both
 * `/oauth/introspect` and `/oauth/token`.
 *
 * Authentication discriminator (RFC 6749 §2.3 / RFC 7591 §2):
 *
 * - `"client_secret_basic"` — credentials in HTTP Basic `Authorization` header.
 * - `"client_secret_post"`  — credentials in form-encoded body parameters.
 * - `"none"`                — public client; only `client_id` (in body) is
 *   supplied. PKCE/S256 is mandated separately at `/authorize` (see `routes.mts`).
 *
 * Enforcement (D-6 PB-2):
 *
 * 1. The configured `tokenEndpointAuthMethod` on the client record selects the
 *    accepted transport. Wrong-transport attempts (e.g. `client_secret_post`
 *    body sent to a `client_secret_basic` client) reject with `invalid_client`
 *    400/401, matching RFC 6749 §5.2.
 * 2. If both Basic and body credentials are present and the `client_id` (or
 *    `client_secret`) values disagree, reject with `invalid_client` 401 —
 *    prevents credential-confusion attacks where an attacker pins a victim's
 *    Basic header and supplies their own body credentials, or vice versa.
 * 3. `WWW-Authenticate: Basic realm="<issuer>"` is emitted in two cases:
 *    (a) the failed attempt was Basic (RFC 7235 §2.1 challenge advertisement),
 *    and (b) no credentials were supplied at all (so the caller is told that
 *    Basic is an accepted retry transport). It is NOT emitted on
 *    `client_secret_post` failures or public-client rejections — those callers
 *    should not be redirected to Basic. The `<issuer>` realm value is
 *    validated against a safe character set; misconfigured issuers fall back
 *    to the literal `oauth` realm.
 *
 * On success: sets `req.oauthClient` to the authenticated {@link PublicClient}
 * and calls `next()`.
 *
 * On failure: responds with 400/401, JSON body
 * `{ error: "invalid_client", error_description?: string }`, and (when
 * applicable) `WWW-Authenticate`. The repository-throw path intentionally omits
 * `error_description` so that internal store details do not leak to callers.
 */
export function createClientAuthMiddleware(
	clientRepository: ClientRepository,
	loggerOrOptions: Logger | ClientAuthMiddlewareOptions = {},
): RequestHandler {
	// Backward-compat: F1 D-4 callers passed the Logger directly. Accept either
	// form to avoid forcing every call site to migrate at once. New call sites
	// SHOULD pass the options object so they can supply `issuer` for the
	// realm parameter.
	const opts: ClientAuthMiddlewareOptions =
		typeof loggerOrOptions === "object" && "warn" in loggerOrOptions
			? { logger: loggerOrOptions as Logger }
			: (loggerOrOptions as ClientAuthMiddlewareOptions);
	const logger: Logger = opts.logger ?? consoleLogger;
	// Copilot review: validate `issuer` against a safe character set before
	// embedding it into the `WWW-Authenticate: Basic realm="..."` quoted-string.
	// RFC 7235 §2.2 + RFC 7230 quoted-string rules require backslash-escaping of
	// `"` and `\` and forbid CTL bytes; rather than emitting a malformed (or
	// header-injecting) value when an operator misconfigures the issuer, we
	// fall back to the literal "oauth" realm. URI-safe characters per RFC 3986
	// (plus the few sub-delims commonly seen in absolute URIs) are accepted.
	const SAFE_REALM_CHARS = /^[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$/;
	const realm =
		opts.issuer && opts.issuer.length > 0 && SAFE_REALM_CHARS.test(opts.issuer)
			? opts.issuer
			: "oauth";
	const wwwAuth = `Basic realm="${realm}"`;
	const allowPublicClients = opts.allowPublicClients === true;

	function rejectBasic(res: Response, status: number, errorDescription?: string): void {
		res.set("WWW-Authenticate", wwwAuth);
		const body: { error: string; error_description?: string } = { error: "invalid_client" };
		if (errorDescription !== undefined) body.error_description = errorDescription;
		res.status(status).json(body);
	}

	function rejectPlain(res: Response, status: number, errorDescription?: string): void {
		const body: { error: string; error_description?: string } = { error: "invalid_client" };
		if (errorDescription !== undefined) body.error_description = errorDescription;
		res.status(status).json(body);
	}

	return async (req, res, next) => {
		const basic = parseBasicAuthHeader(req.headers.authorization);

		if (basic.kind === "malformed") {
			rejectBasic(res, 401, "Malformed client credentials");
			return;
		}

		// RFC 7617 §2: Basic auth with an empty secret is a malformed credential.
		// `ClientEntrySchema` already rejects empty `clientSecret` at startup, so
		// any production deployment that has wired `clientAuthMw` cannot emit one
		// — but rejecting the empty case at the parser keeps the contract uniform
		// with the v0.5.0 behaviour and avoids exposing an "empty == empty" path
		// through `authenticate()` for misconfigured custom repositories.
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

		// Codex M4: conflict detection. If both Basic and body identify a client,
		// they MUST agree. Otherwise the request is ambiguous and an attacker
		// could pin one identity in a header (typically less inspected by
		// proxies) while sending another in the body.
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
			// Distinguish the no-credentials-at-all path from a malformed Basic.
			// We always include WWW-Authenticate because Basic is a valid retry,
			// matching prior v0.5.0 behavior for the /oauth/introspect users.
			rejectBasic(res, 401, "Client authentication is required");
			return;
		}

		// Codex M1 selector: which transport did the caller actually use? We
		// have to derive this BEFORE looking up the client so the wrong-method
		// branch can return without burning a credential lookup on a known-bad
		// transport.
		const usedMethod: TokenEndpointAuthMethod =
			basic.kind === "ok"
				? "client_secret_basic"
				: bodyClientSecret !== undefined
					? "client_secret_post"
					: "none";

		// Look up the client without authenticating yet — `findById` returns the
		// same projection regardless of method, and we need the configured
		// `tokenEndpointAuthMethod` to gate the credential check below. For
		// `"client_secret_basic"` / `"client_secret_post"` clients we still call
		// `authenticate()` afterward to verify the secret; for `"none"` clients
		// the `findById` result is the final answer.
		let client: PublicClient | null;
		try {
			client = await clientRepository.findById(clientId);
		} catch (err) {
			// Fail-closed: repository unavailability must not grant access.
			logger.warn({ err }, "client lookup failed");
			if (basic.kind === "ok") {
				rejectBasic(res, 401);
			} else {
				rejectPlain(res, 401);
			}
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

		// Codex M1: configured method must match the transport actually used.
		// A `client_secret_basic` client cannot succeed via body auth, and vice
		// versa — even with valid credentials. This makes the discriminator
		// authoritative; without it the field would be partly documentary.
		if (client.tokenEndpointAuthMethod !== usedMethod) {
			const description =
				usedMethod === "none"
					? "Client authentication is required for confidential clients"
					: `tokenEndpointAuthMethod mismatch: client is configured for "${client.tokenEndpointAuthMethod}"`;
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
			logger.warn({ err }, "client credential lookup failed");
			if (basic.kind === "ok") {
				rejectBasic(res, 401);
			} else {
				rejectPlain(res, 401);
			}
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
