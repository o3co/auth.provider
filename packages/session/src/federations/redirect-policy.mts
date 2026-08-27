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

import type { ProviderDeps } from "@o3co/auth-provider-core";
import type { RedirectConfig } from "./helpers.mjs";
import { resolveCallbackRedirect } from "./helpers.mjs";
import type { FederationResult } from "./types.mjs";

/**
 * Where a consumer-supplied `redirect_to` is checked against the deployment's
 * policy.
 *
 * ## Why an allowlist, and why it fails closed
 *
 * The pre-#278 rule was "any absolute http(s) URL, narrowed to `sessionDomain`
 * **if one is configured**". `sessionDomain` is optional and defaults to
 * absent, so the shipped default admitted every http(s) URL on the internet.
 * `/session/oauth/federation/:name?redirect_to=…` therefore let anyone hand a
 * victim a link that authenticates at the real IdP and then lands the browser
 * on an attacker's page — the textbook open redirect, and here with a freshly
 * minted session behind it.
 *
 * So the allowlist is now the authority, and an **absent allowlist is the
 * empty allowlist**: no `redirect_to` value is accepted at all. Nothing falls
 * back to "any http(s) URL", because a fallback is exactly how the permissive
 * branch survived being written down as a rule. A deployment that never
 * accepts `redirect_to` needs no configuration and keeps working; one that
 * does must say which targets it means.
 *
 * ## Exact match
 *
 * A candidate matches when its **normalized** form equals an entry's. The
 * normalization is `new URL(x).href`, so scheme and host case, the default
 * port, `..` segments and percent-encoding are insignificant, and everything
 * else — path, query, fragment, port — is significant. There is no prefix,
 * suffix, wildcard or subdomain matching: `https://app.example.com/dashboard`
 * does not admit `…/dashboard?next=//evil.com`, and an entry does not admit
 * its own siblings. That is deliberately strict, because every relaxation of
 * redirect matching that has ever shipped anywhere has turned out to be an
 * open redirect in a costume.
 *
 * The consequence for operators is that a target carrying dynamic query
 * parameters cannot be allowlisted as a family; it has to become a fixed path
 * with the variable part carried in the session instead.
 *
 * ## The loopback carve-out
 *
 * `http://` is accepted for **loopback hosts only** — `localhost`, anything in
 * `127.0.0.0/8`, and `[::1]` — matching `checkSecureEndpoint`
 * (`@o3co/auth-provider-foundation`, #285) and `checkCanonicalIssuer`
 * (`@o3co/auth-provider-core`). Native clients redirect to a loopback listener
 * (RFC 8252 §7.3) and local development serves the consumer app over plain
 * HTTP; neither can obtain a certificate, and traffic to a loopback address
 * never leaves the machine, so there is nothing on that path to eavesdrop on.
 * Any other host must use `https://` — including a private-range address or a
 * container-network service name, which do cross a network the deployment does
 * not control end to end.
 *
 * The carve-out is about the **scheme**, not the matching: a loopback entry is
 * still matched exactly, port included. RFC 8252 §7.3's port-agnostic loopback
 * comparison is deliberately **not** implemented — `redirect_to` here is the
 * consumer app's landing page, whose port a development or native setup knows
 * in advance, so a port wildcard would widen the surface to buy nothing.
 *
 * ## `sessionDomain`
 *
 * `sessionDomain` is the cookie domain, and before #278 it was the only
 * constraint on a redirect target. It survives as a **narrowing** check on the
 * allowlist itself, applied when the policy is constructed: an entry outside
 * the configured domain is refused at boot rather than sitting in the config
 * looking effective. Dropping it instead would have silently widened what
 * existing deployments accept, which a security fix must not do. Loopback
 * entries are exempt, because a native client's `http://127.0.0.1:PORT` can
 * never be inside a cookie domain and is precisely the case the carve-out
 * exists for — applying the domain check to it would make the carve-out
 * unreachable for every deployment that sets `sessionDomain`.
 *
 * An operator who genuinely needs a cross-domain redirect target unsets
 * `sessionDomain`, which is then an explicit decision rather than a silent one.
 *
 * ## Why the loopback rule is spelled out again here
 *
 * `isLoopbackHostname` duplicates `@o3co/auth-provider-foundation`'s copy
 * rather than importing it: `foundation` is an adapter package that does not
 * re-export the helper, and `session` has no dependency edge to it. Adding one
 * to reach ten lines would point the dependency graph the wrong way. The
 * *rule* is the same one on purpose — an operator meets one loopback policy
 * across this repository, not three — and the rejection vocabulary below
 * follows `checkSecureEndpoint`'s (`<reason>` token plus an operator-facing
 * sentence that states the actual rule) rather than inventing a dialect.
 */

/** The longest `redirect_to` accepted, checked before the value is parsed. */
export const MAX_REDIRECT_URL_LENGTH = 2048;

/** Matches `scheme://` — the shape that distinguishes an absolute URL from a path or a bare host. */
const ABSOLUTE_URL_PREFIX = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

/** Dotted-quad IPv4, the only numeric form the WHATWG URL parser emits. */
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Whether `hostname` — as `URL.hostname` reports it, so IPv6 arrives bracketed
 * and IPv4 shorthand has already been normalized to dotted quad — names an
 * address that never leaves the machine.
 */
export function isLoopbackHostname(hostname: string): boolean {
	if (hostname === "localhost") return true;
	if (hostname === "[::1]" || hostname === "::1") return true;

	const v4 = IPV4.exec(hostname);
	if (v4 === null) return false;
	// The whole 127.0.0.0/8 block is loopback, not just 127.0.0.1.
	const octets = [v4[1], v4[2], v4[3], v4[4]].map(Number);
	return octets[0] === 127 && octets.every((o) => o <= 255);
}

/**
 * Why a redirect target was refused.
 *
 * The first seven are shape faults and apply both to a request-time candidate
 * and to an allowlist entry. `outside-session-domain` only ever applies to an
 * entry (it is checked when the policy is built); `no-allowlist` and
 * `not-allowlisted` only ever apply to a candidate.
 */
export type RedirectRejection =
	| "not-a-string"
	| "empty"
	| "too-long"
	| "not-absolute-url"
	| "unsupported-scheme"
	| "insecure-scheme"
	| "has-credentials"
	| "outside-session-domain"
	| "no-allowlist"
	| "not-allowlisted";

/**
 * Operator-facing explanation for each rejection reason.
 *
 * Every message states the **actual** rule rather than a simplification of it —
 * in particular both scheme messages name the loopback carve-out, because
 * "must use https" would contradict a policy that does accept `http://` on
 * loopback and send someone hunting for a certificate they do not need.
 */
export function describeRedirectRejection(reason: RedirectRejection): string {
	switch (reason) {
		case "not-a-string":
			return "must be a string";
		case "empty":
			return "must not be empty";
		case "too-long":
			return `must be at most ${MAX_REDIRECT_URL_LENGTH} characters`;
		case "not-absolute-url":
			return (
				"must be an absolute URL with a host (e.g. https://app.example.com/welcome), " +
				"not a path, a bare host, or a protocol-relative reference"
			);
		case "unsupported-scheme":
			return (
				"must use https, or http for a loopback host (localhost, 127.0.0.0/8, [::1]) — " +
				"no other scheme is accepted"
			);
		case "insecure-scheme":
			return (
				"must use https — http is accepted only for a loopback host " +
				"(localhost, 127.0.0.0/8, [::1]), where the traffic never leaves the machine"
			);
		case "has-credentials":
			return "must not embed credentials in the URL";
		case "outside-session-domain":
			return (
				"must be inside the configured sessionDomain, or name a loopback host — " +
				"a target the session cookie cannot reach would land the user logged out"
			);
		case "no-allowlist":
			return (
				"is refused because this federation has no redirect allowlist: set " +
				"redirectAllowlist to the exact URLs this deployment may redirect to"
			);
		case "not-allowlisted":
			return "must exactly match an entry in this federation's redirect allowlist";
	}
}

/**
 * Returns `null` when `value` is well-formed enough to be a redirect target,
 * otherwise the reason it is not. Shared by allowlist entries and request-time
 * candidates so the two can never drift apart.
 */
function checkRedirectShape(value: unknown): RedirectRejection | null {
	if (typeof value !== "string") return "not-a-string";
	if (value === "") return "empty";
	// Length first: the cap is a bound on the work done below, so it has to be
	// checked before anything parses the value.
	if (value.length > MAX_REDIRECT_URL_LENGTH) return "too-long";

	// `new URL("app.example.com:3000")` succeeds with `app.example.com:` as the
	// scheme and no host, and `new URL("javascript:alert(1)")` succeeds outright.
	// Requiring `scheme://` reports both as the missing-scheme mistake they are
	// rather than letting them reach the scheme check as exotic schemes.
	if (!ABSOLUTE_URL_PREFIX.test(value)) return "not-absolute-url";

	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return "not-absolute-url";
	}

	if (url.protocol !== "https:" && url.protocol !== "http:") return "unsupported-scheme";
	// No empty-host check is needed: `http` and `https` are "special" schemes,
	// for which the WHATWG parser requires a non-empty host — a host-less
	// `https://` throws above and is reported as `not-absolute-url`.
	if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) return "insecure-scheme";
	// `https://app.example.com@evil.com/` parses with host `evil.com`: the
	// familiar-looking prefix is userinfo. Exact matching already refuses it,
	// but naming it explicitly beats reporting it as a missing allowlist entry.
	if (url.username !== "" || url.password !== "") return "has-credentials";

	return null;
}

/** `URL.hostname` is inside `sessionDomain` (leading dot insignificant), or is loopback. */
function isInsideSessionDomain(hostname: string, sessionDomain: string): boolean {
	if (isLoopbackHostname(hostname)) return true;
	const normalized = sessionDomain.replace(/^\./, "");
	return hostname === normalized || hostname.endsWith(`.${normalized}`);
}

/**
 * Consumer-facing redirect URL validation and callback redirect resolution.
 *
 * Distinct from `FederationProvider` (upstream IdP protocol) — this interface
 * is the consumer's allowed-redirect-URL policy for a named federation.
 * Consumers can replace this independently of the IdP integration.
 *
 * Per A5 §5.2.
 */
export interface FederationRedirectPolicy {
	/**
	 * Validation for a consumer-supplied `redirect_to`.
	 *
	 * Returns `{ ok: true }` when the URL passes the policy's allowlist;
	 * otherwise returns a `FederationResult` failure with HTTP status code,
	 * OAuth error code, and error description suitable for direct response.
	 *
	 * An implementation MUST fail closed: refuse everything it has not been
	 * told to permit. The default implementation below does; a replacement that
	 * accepts "any URL that parses" reopens #278.
	 */
	validateRedirect(url: string): FederationResult<void>;

	/**
	 * Resolve the post-callback redirect URL from the session's `redirectTo`.
	 *
	 * Returns `{ ok: true, value: string }` with the resolved redirect URL on
	 * success; otherwise returns a `FederationResult` failure.
	 *
	 * Same behavior contract as the v0.4.x `FederationProvider.resolveCallbackRedirect`
	 * method that this replaces.
	 */
	resolveCallbackRedirect(session: { readonly redirectTo?: string }): FederationResult<string>;
}

/**
 * Per-contribution factory type for `federationRedirectPolicies` contributions.
 * Follows the A2-α §4.1 contribution-factory pattern.
 *
 * Per A5 §5.3.
 */
export type FederationRedirectPolicyFactory<Deps = ProviderDeps<never, never>> = (
	deps: Deps,
) => FederationRedirectPolicy;

/**
 * Config slice consumed by the redirect policy.
 *
 *   - `redirectAllowlist`: the exact URLs a `redirect_to` may name. Absent or
 *     empty means *nothing* is accepted — see the module comment.
 *   - `sessionDomain`: cookie domain; every non-loopback allowlist entry must
 *     be inside it, checked when the policy is built.
 *   - `authCallbackUrl`: post-callback bridge endpoint that wraps a
 *     consumer-supplied `redirect_to` query parameter.
 *   - `clientUrl`: fallback redirect when session has no `redirectTo`.
 *
 * A `Pick<RedirectConfig, ...>` projection limits the policy to the fields it
 * actually consumes.
 */
export type FederationRedirectPolicyConfig = Pick<
	RedirectConfig,
	"redirectAllowlist" | "sessionDomain" | "authCallbackUrl" | "clientUrl"
>;

/**
 * Builds the set of normalized allowlist entries, refusing any entry that
 * could never legitimately match.
 *
 * Entry validation is eager, and it throws rather than dropping the entry:
 * an operator who lists a target and sees redirects refused anyway has no way
 * to tell a typo from a policy they misunderstood, and a silently dead
 * allowlist entry is how a deployment ends up believing it is configured.
 *
 * The offending entry is identified by **index, not value**: an entry may
 * embed credentials (that is one of the things being refused) and this message
 * lands in boot logs. The index plus the reason is enough to find it.
 */
function normalizeAllowlist(
	entries: readonly string[] | undefined,
	sessionDomain: string | undefined,
): ReadonlySet<string> {
	if (entries === undefined) return new Set();
	if (!Array.isArray(entries)) {
		throw new Error(
			"createFederationRedirectPolicy: redirectAllowlist must be an array of URL strings",
		);
	}

	const normalized = new Set<string>();
	for (const [index, entry] of entries.entries()) {
		const reject = (reason: RedirectRejection): never => {
			throw new Error(
				`createFederationRedirectPolicy: redirectAllowlist[${index}] ` +
					`${describeRedirectRejection(reason)} (reason: ${reason})`,
			);
		};

		const shape = checkRedirectShape(entry);
		if (shape !== null) reject(shape);

		const url = new URL(entry);
		if (sessionDomain !== undefined && sessionDomain !== "") {
			if (!isInsideSessionDomain(url.hostname, sessionDomain)) reject("outside-session-domain");
		}
		normalized.add(url.href);
	}
	return normalized;
}

/**
 * Default `FederationRedirectPolicy` factory.
 *
 * Provider configs (`GoogleProviderConfig`, `GithubProviderConfig`) are
 * structurally assignable, so the full provider config can be passed.
 *
 * Throws when `redirectAllowlist` holds an entry that could never match — see
 * `normalizeAllowlist`. An **absent** allowlist does not throw: a deployment
 * that never accepts `redirect_to` is correctly configured, and its refusal
 * surfaces on the request that actually asks for a redirect.
 */
export function createFederationRedirectPolicy(
	config: FederationRedirectPolicyConfig,
): FederationRedirectPolicy {
	// Defensive snapshot: detach from the caller's reference so post-construction
	// mutation of the supplied config (e.g. `config.sessionDomain = "evil.com"`
	// later) cannot retroactively change behaviour. The allowlist is copied into
	// a Set for the same reason — freezing the config object would still leave
	// the caller's array mutable through its own reference.
	const frozenConfig = Object.freeze({ ...config });
	const allowlist = normalizeAllowlist(frozenConfig.redirectAllowlist, frozenConfig.sessionDomain);

	const refuse = (reason: RedirectRejection): FederationResult<void> => ({
		ok: false,
		status: 400,
		error: "invalid_redirect",
		errorDescription: `redirect_to ${describeRedirectRejection(reason)} (reason: ${reason})`,
	});

	return Object.freeze({
		validateRedirect(url: string): FederationResult<void> {
			const shape = checkRedirectShape(url);
			if (shape !== null) return refuse(shape);

			// Fail closed. An unconfigured allowlist is the empty allowlist, and
			// it is reported as its own reason so an operator reading the response
			// or the log can tell "nothing is configured" from "your URL is not on
			// the list" without guessing.
			if (allowlist.size === 0) return refuse("no-allowlist");
			if (!allowlist.has(new URL(url).href)) return refuse("not-allowlisted");

			return { ok: true, value: undefined };
		},
		resolveCallbackRedirect(session: { readonly redirectTo?: string }): FederationResult<string> {
			return resolveCallbackRedirect(session, frozenConfig);
		},
	});
}
