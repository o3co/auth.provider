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
 * The client (RFC 6749 §4.1.1): `client_id`, the `redirect_uri` allowlist and
 * what the registration permits here. Until `redirect_uri` is validated no
 * redirect target is trusted, so identification answers 400/503 JSON.
 */

import {
	auditErrorText,
	checkRedirectUri,
	isGrantTypeAllowed,
	isWellFormedClientId,
	logClientRepositoryUnavailable,
	matchesRegisteredRedirectUri,
	type PublicClient,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { auditFailure, redirectError } from "./authorizeAnswers.mjs";
import {
	type AuthorizeContext,
	type AuthorizeHandlerOptions,
	authorizeParams,
} from "./authorizeContext.mjs";

/**
 * RFC 6749 §4.1.1 identification: `client_id`/`redirect_uri` presence, client
 * lookup and the `redirect_uri` allowlist, then core's `checkRedirectUri` on
 * the matched URI. Everything here answers 400/503 JSON because no trusted
 * redirect target exists yet. A malformed `client_id` is answered as unknown
 * and never reaches the repository (which may throw on it); a repository that
 * throws is `503 temporarily_unavailable`.
 *
 * Returns `null` when a response has been sent.
 */
export const resolveClientAndRedirectUri = async (
	req: Request,
	res: Response,
	opts: AuthorizeHandlerOptions,
): Promise<{ client: PublicClient; clientId: string; redirectUri: string } | null> => {
	const { client_id = null, redirect_uri = null } = authorizeParams(req);

	// Invalid client_id or redirect_uri → 400 JSON (cannot redirect).
	if (typeof client_id !== "string" || !client_id) {
		res.status(400).json({ error: "invalid_request", error_description: "client_id is required" });
		return null;
	}

	if (typeof redirect_uri !== "string" || !redirect_uri) {
		res
			.status(400)
			.json({ error: "invalid_request", error_description: "redirect_uri is required" });
		return null;
	}

	if (!isWellFormedClientId(client_id)) {
		res.status(400).json({ error: "invalid_client", error_description: "client not found" });
		return null;
	}

	let client: PublicClient | null;
	try {
		client = await opts.clientRepository.findById(client_id);
	} catch (err) {
		// The client's id is its own input: recorded sanitised and capped.
		logClientRepositoryUnavailable(
			opts.logger,
			{ site: "authorize", step: "find", clientId: client_id },
			err,
		);
		res.status(503).json({
			error: "temporarily_unavailable",
			error_description: "client repository unavailable",
		});
		return null;
	}
	if (!client) {
		// Cannot redirect — client unknown, redirect_uri untrusted
		res.status(400).json({ error: "invalid_client", error_description: "client not found" });
		return null;
	}

	// Exact string equality, except that an `http:` loopback IP literal on both
	// sides is compared without the port — a native app's listener binds an
	// ephemeral port the registration cannot name (RFC 8252 §7.3). `localhost`
	// and `https:` get no carve-out. The PRESENTED URI is bound to the code, so
	// the token endpoint's §4.1.3 equality check compares the URI actually used.
	if (
		!client.allowedRedirectUris.some((entry) => matchesRegisteredRedirectUri(entry, redirect_uri))
	) {
		// Cannot redirect — redirect_uri not trusted
		res
			.status(400)
			.json({ error: "invalid_request", error_description: "redirect_uri not allowed" });
		return null;
	}

	// Registered, and still held to what registration refuses: a custom
	// repository bypasses `ClientEntrySchema`. The presented URI is checked; it
	// differs from the matched entry at most in a loopback port, which the
	// check does not read. Answered as an unregistered URI is, and never
	// redirected to (RFC 6749 §4.1.2.1).
	const rejection = checkRedirectUri(redirect_uri);
	if (rejection !== null) {
		opts.logger.warn(
			{ site: "authorize", clientId: auditErrorText(client_id), reason: rejection.reason },
			"authorize_registered_redirect_uri_refused",
		);
		res
			.status(400)
			.json({ error: "invalid_request", error_description: "redirect_uri not allowed" });
		return null;
	}

	return { client, clientId: client_id, redirectUri: redirect_uri };
};

// The code flow leads to `grant_type=authorization_code`, so a client not
// registered for it is refused here, before the user authenticates and a code
// is minted.
export const checkAuthorizationCodeGrantAllowed = async (
	ctx: AuthorizeContext,
	client: PublicClient,
): Promise<boolean> => {
	if (
		isGrantTypeAllowed(client.allowedGrantTypes, "authorization_code", {
			requireAllowlist: ctx.opts.oauth.requireGrantTypeAllowlist,
		})
	)
		return true;
	await auditFailure(ctx, { reason: "grant_type_not_allowed", grant_type: "authorization_code" });
	// The token endpoint's words for the same refusal.
	redirectError(
		ctx,
		"unauthorized_client",
		"client is not authorized for grant_type 'authorization_code'",
	);
	return false;
};

// A client that is not first-party is served only through consent, so without
// a consent store it is refused here, ahead of the request-shape checks.
export const checkFirstPartyOrConsentable = async (
	ctx: AuthorizeContext,
	client: PublicClient,
): Promise<boolean> => {
	if (client.firstParty === true || ctx.opts.consentStore !== undefined) return true;
	await auditFailure(ctx, { reason: "client_not_first_party" });
	redirectError(
		ctx,
		"unauthorized_client",
		"client is not authorized for the authorization endpoint",
	);
	return false;
};
