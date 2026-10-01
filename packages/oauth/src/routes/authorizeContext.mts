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
 * What every `/authorize` stage reads: the handler's options, the request's
 * parameters and its GET URL on the issuer's origin, and the per-request
 * context, which exists only once `redirect_uri` is validated.
 */

import {
	type AuditSink,
	buildCanonicalRequestUrl,
	type ClientRepository,
	type CodeRepository,
	type ConsentStore,
	type GrantPolicyHook,
	type Logger,
	type LoginEntry,
	type PendingConsentStore,
	readSpaceDelimitedParameter,
	type SessionRequirementResolver,
	type SubjectRevocation,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { ResolvedOAuthOptions } from "../resolveOAuthOptions.mjs";

export interface AuthorizeHandlerOptions {
	readonly clientRepository: ClientRepository;
	readonly codeRepository: CodeRepository;
	readonly grantPolicy?: GrantPolicyHook;
	readonly auditSink?: AuditSink;
	readonly logger: Logger;
	/** The canonical issuer, config-only: never request-derived (Host is attacker-controlled). */
	readonly issuer: string;
	/** The `iss` every authorization response carries (RFC 9207): the issuer as discovery advertises it. */
	readonly authorizationResponseIssuer: string;
	/**
	 * The login trip for a browser that must log in: `urlFor(returnTo)` is the
	 * login page with the request to come back to — the `loginEntry` slot's.
	 */
	readonly login: Pick<LoginEntry, "urlFor">;
	/**
	 * Consent-page URL for a client that is not first-party. A thunk, evaluated
	 * per request.
	 */
	readonly consentUrl: () => string;
	/** Where consent records live. Without it a client that is not first-party is refused. */
	readonly consentStore?: ConsentStore;
	/**
	 * Where a request is parked while the consent page asks. Wired with
	 * `consentStore`; the router refuses one without the other.
	 */
	readonly pendingConsentStore?: PendingConsentStore;
	/** The `oauth.*` knobs, resolved once at router composition. */
	readonly oauth: ResolvedOAuthOptions;
	/**
	 * The durable session store admission reads the cookie's session from.
	 * Without it (no session-backed login) admission decides on the cookie alone.
	 */
	readonly userSessionStore?: UserSessionStore;
	/**
	 * The subject-revocation boundary admission applies to the live record: a
	 * session established before the subject's sessions were revoked is refused
	 * here too, not only at the token side.
	 */
	readonly subjectRevocation?: SubjectRevocation;
	/**
	 * The registered session requirements admission asks about. Required: a
	 * handler built without one is refused.
	 */
	readonly requirements: SessionRequirementResolver;
}

/**
 * Per-request state threaded through the §4.1 stages. Constructed only
 * after `resolveClientAndRedirectUri` validated `redirect_uri` against the
 * client allowlist, so holding it is itself the proof that redirect-based
 * errors (RFC 6749 §4.1.2.1) are permitted.
 */
export interface AuthorizeContext {
	readonly req: Request;
	readonly res: Response;
	readonly opts: AuthorizeHandlerOptions;
	/** The configured issuer's origin — what a parked request's URL is built from. */
	readonly issuerOrigin: string;
	readonly clientId: string;
	readonly redirectUri: string;
	/** Verbatim `state` when it was a single string; echoed on every response. */
	readonly state: string | undefined;
	/**
	 * The request's parameters — query string on GET, form body on POST — so
	 * every check reads the same object however the request arrived.
	 */
	readonly params: Record<string, unknown>;
}

export const toStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

/**
 * The authorization request's parameters: a POST's form body or a GET's
 * query (OIDC Core §3.1.2.1 requires both methods). Read in one place so no
 * check silently applies to GET alone.
 */
export const authorizeParams = (req: Request): Record<string, unknown> =>
	req.method === "POST"
		? ((req.body ?? {}) as Record<string, unknown>)
		: (req.query as Record<string, unknown>);

/**
 * This authorization request as a GET URL on the issuer's origin, with a
 * POST's form parameters written as the query: what the consent, login and
 * step-up pages return to, and what an ask is bound to. Not
 * `req.originalUrl`: a POST's URL alone names no client, `redirect_uri` or
 * PKCE.
 */
export const authorizeRequestUrl = (issuerOrigin: string, req: Request): URL => {
	const url = new URL(buildCanonicalRequestUrl(issuerOrigin, req.originalUrl));
	url.search = "";
	for (const [name, value] of Object.entries(authorizeParams(req))) {
		if (typeof value === "string") {
			url.searchParams.append(name, value);
		} else if (Array.isArray(value)) {
			for (const item of value) {
				if (typeof item === "string") url.searchParams.append(name, item);
			}
		}
	}
	return url;
};

/**
 * `url` less `prompt=consent`, which the consent round trip answers — carried
 * back, it would park the request again forever. Other prompt values stay,
 * read as `resolvePrompt` reads them; a malformed `prompt` was refused there
 * and is left as it is. The request the consent step resumes, and the one a
 * re-authentication ask is bound to, so the two agree.
 */
export const withoutConsentPrompt = (url: URL): URL => {
	const out = new URL(url);
	const prompt = out.searchParams.get("prompt");
	const prompts = prompt === null ? null : readSpaceDelimitedParameter(prompt);
	if (prompts === null) return out;
	const remaining = prompts.filter((value) => value !== "consent");
	if (remaining.length === 0) {
		out.searchParams.delete("prompt");
	} else {
		out.searchParams.set("prompt", remaining.join(" "));
	}
	return out;
};
