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

import { isLoopbackHostname } from "@o3co/auth-provider-core";
import type { FederationResult } from "./federations/types.mjs";

/**
 * The one place a consumer-supplied `redirect_to` is checked against the
 * deployment's policy. Both entry points (the federation start and
 * `POST /session/login`) build their validator here, so the rule cannot hold
 * on one and not the other.
 *
 * Fail closed: an absent allowlist is the empty allowlist, and no
 * `redirect_to` is accepted. There is no "any http(s) URL" fallback — that
 * is the open redirect this module exists to prevent.
 *
 * Exact match on the normalized form (`new URL(x).href`): scheme and host
 * case, the default port, `..` and percent-encoding are insignificant; path,
 * query, fragment and port are significant. No prefix, wildcard or subdomain
 * matching — every such relaxation has turned out to be an open redirect. A
 * target with dynamic query parameters must become a fixed path, with the
 * variable part carried in the session.
 *
 * `http://` is accepted only for loopback hosts (core's
 * `isLoopbackHostname`, as `checkSecureEndpoint` and `checkCanonicalIssuer`
 * use): native clients (RFC 8252 §7.3) and local development cannot get
 * certificates, and loopback traffic never leaves the machine. The carve-out
 * is about the scheme only; the port still matches exactly.
 *
 * The session cookie domain narrows the allowlist at construction: a
 * non-loopback entry outside it is refused at boot rather than sitting in the
 * config looking effective. A cross-domain target requires unsetting the
 * cookie domain, an explicit decision.
 */

// Re-exported unchanged: this package's index surfaces it as public API; the
// definition is core's.
export { isLoopbackHostname };

/** The longest `redirect_to` accepted, checked before the value is parsed. */
export const MAX_REDIRECT_URL_LENGTH = 2048;

/** Matches `scheme://` — the shape that distinguishes an absolute URL from a path or a bare host. */
const ABSOLUTE_URL_PREFIX = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

/**
 * How the allowlist config key is named back to an operator when a redirect is
 * refused. A federation policy cannot name its own federation (it is built from
 * a config slice that does not carry the name), so it says "the federation's".
 */
const DEFAULT_ALLOWLIST_CONFIG_KEY = "the federation's redirectAllowlist";

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
 * Operator-facing explanation for each rejection reason. Each states the
 * actual rule (the scheme messages name the loopback carve-out).
 * `allowlistConfigKey` names the config path to edit, since the two entry
 * points are configured in different places. Printable ASCII without `"` or
 * `\`: it becomes an `error_description` (RFC 6749 Appendix A.8).
 */
export function describeRedirectRejection(
	reason: RedirectRejection,
	options: { readonly allowlistConfigKey?: string } = {},
): string {
	const allowlistConfigKey = options.allowlistConfigKey ?? DEFAULT_ALLOWLIST_CONFIG_KEY;
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
				"must use https, or http for a loopback host (localhost, 127.0.0.0/8, [::1]); " +
				"no other scheme is accepted"
			);
		case "insecure-scheme":
			return (
				"must use https; http is accepted only for a loopback host " +
				"(localhost, 127.0.0.0/8, [::1]), where the traffic never leaves the machine"
			);
		case "has-credentials":
			return "must not embed credentials in the URL";
		case "outside-session-domain":
			return (
				"must be inside the configured session cookie domain, or name a loopback host; " +
				"a target the session cookie cannot reach would land the user logged out"
			);
		case "no-allowlist":
			return (
				`is refused because no redirect allowlist is configured: set ${allowlistConfigKey} ` +
				"to the exact URLs this deployment may redirect to"
			);
		case "not-allowlisted":
			return `must exactly match an entry in ${allowlistConfigKey}`;
	}
}

/**
 * Returns `null` when `value` is well-formed enough to be a redirect target,
 * otherwise the reason it is not. Shared by allowlist entries and request-time
 * candidates so the two can never drift apart.
 */
export function checkRedirectShape(value: unknown): RedirectRejection | null {
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

/** `URL.hostname` is inside the cookie domain (leading dot insignificant), or is loopback. */
function isInsideSessionDomain(hostname: string, sessionDomain: string): boolean {
	if (isLoopbackHostname(hostname)) return true;
	const normalized = sessionDomain.replace(/^\./, "");
	return hostname === normalized || hostname.endsWith(`.${normalized}`);
}

/**
 * What a redirect allowlist is built from.
 *
 *   - `redirectAllowlist`: the exact URLs a `redirect_to` may name; absent or
 *     empty accepts nothing.
 *   - `sessionDomain`: every non-loopback entry must be inside it. `null` and
 *     `""` mean absent, so both config spellings behave alike.
 *   - `allowlistConfigKey`: the config path named back on a refusal.
 *   - `factoryName`: prefix for the boot-time entry-rejection message.
 */
export interface RedirectAllowlistOptions {
	readonly redirectAllowlist?: readonly string[] | undefined;
	readonly sessionDomain?: string | null | undefined;
	readonly allowlistConfigKey?: string | undefined;
	readonly factoryName: string;
}

/** Validation for a consumer-supplied `redirect_to`. */
export interface RedirectAllowlistValidator {
	/**
	 * Returns `{ ok: true }` when the URL passes the allowlist; otherwise a
	 * failure carrying HTTP status, OAuth error code and description suitable
	 * for direct response.
	 */
	validateRedirect(url: string): FederationResult<void>;
}

/**
 * Normalizes the allowlist, throwing on any entry that could never
 * legitimately match: a silently dead entry leaves a deployment believing it
 * is configured. Entries are named by index, not value, since an entry may
 * embed credentials and the message lands in boot logs.
 */
function normalizeAllowlist(
	entries: readonly string[] | undefined,
	sessionDomain: string | null | undefined,
	factoryName: string,
	allowlistConfigKey: string,
): ReadonlySet<string> {
	if (entries === undefined) return new Set();
	if (!Array.isArray(entries)) {
		throw new Error(`${factoryName}: redirectAllowlist must be an array of URL strings`);
	}

	const normalized = new Set<string>();
	for (const [index, entry] of entries.entries()) {
		const reject = (reason: RedirectRejection): never => {
			throw new Error(
				`${factoryName}: redirectAllowlist[${index}] ` +
					`${describeRedirectRejection(reason, { allowlistConfigKey })} (reason: ${reason})`,
			);
		};

		const shape = checkRedirectShape(entry);
		if (shape !== null) reject(shape);

		const url = new URL(entry);
		if (sessionDomain !== undefined && sessionDomain !== null && sessionDomain !== "") {
			if (!isInsideSessionDomain(url.hostname, sessionDomain)) reject("outside-session-domain");
		}
		normalized.add(url.href);
	}
	return normalized;
}

/**
 * Builds the exact-match, fail-closed redirect validator both entry points run.
 *
 * Throws when `redirectAllowlist` holds an entry that could never match — see
 * `normalizeAllowlist`. An **absent** allowlist does not throw: a deployment
 * that never accepts `redirect_to` is correctly configured, and its refusal
 * surfaces on the request that actually asks for a redirect.
 */
export function createRedirectAllowlistValidator(
	options: RedirectAllowlistOptions,
): RedirectAllowlistValidator {
	const allowlistConfigKey = options.allowlistConfigKey ?? DEFAULT_ALLOWLIST_CONFIG_KEY;
	// Defensive snapshot: the allowlist is copied into a Set so post-construction
	// mutation of the caller's array cannot retroactively change behaviour.
	const allowlist = normalizeAllowlist(
		options.redirectAllowlist,
		options.sessionDomain,
		options.factoryName,
		allowlistConfigKey,
	);

	const refuse = (reason: RedirectRejection): FederationResult<void> => ({
		ok: false,
		status: 400,
		error: "invalid_redirect",
		errorDescription: `redirect_to ${describeRedirectRejection(reason, { allowlistConfigKey })} (reason: ${reason})`,
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
	});
}
