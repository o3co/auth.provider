/*
 * Copyright 2026 1o1 Co. Ltd.
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
 * The OIDC Front-Channel Logout 1.0 page: its markup (a hidden iframe per
 * usable relying party and the post-logout redirect) and its own
 * Content-Security-Policy, which allows frames only from the origins it
 * renders (`frame-src`) and the static redirect script only by its hash.
 * `renderFrontchannelLogoutPage`, internal, returns both for the logout route
 * to serve; the public `renderFrontchannelLogoutHtml` returns the markup alone.
 */

import { createHash } from "node:crypto";
import type { Logger, RedirectUriRejection } from "@o3co/auth-provider-core";
import {
	auditErrorText,
	checkRedirectUri,
	guardedRead,
	loggableError,
} from "@o3co/auth-provider-core";
import { usableFrontchannelRP } from "./frontchannelLogoutUri.mjs";

export interface FrontchannelRP {
	readonly clientId: string;
	readonly frontchannelLogoutUri?: string | undefined;
	/** Defaults to `true` — append sid so RPs can correlate sessions. */
	readonly frontchannelLogoutSessionRequired?: boolean | undefined;
}

export interface RenderFrontchannelLogoutHtmlOptions {
	readonly rps: ReadonlyArray<FrontchannelRP>;
	readonly issuer: string;
	readonly sid: string;
	/**
	 * Where the page sends the browser once the iframes have had their time,
	 * as its two parts: `uri`, the registered `post_logout_redirect_uri` the
	 * caller validated, and the RP's `state` (OIDC RP-Initiated Logout 1.0
	 * §3), if any. `uri` is checked here with core's `checkRedirectUri`
	 * exactly as written, the rule the route accepts it by, so one already
	 * carrying `state` is refused; the page then appends a non-empty `state`
	 * itself, through `URLSearchParams`, as the route's own redirect does. A
	 * `uri` the check refuses, a value that is not a string, or a read that
	 * throws leaves the page without its redirect, logged once at warn as
	 * `logout_frontchannel_redirect_refused` with the reason, never the URI.
	 */
	readonly postLogoutRedirect?: {
		readonly uri: string;
		readonly state?: string | undefined;
	};
	/** Defaults to 2000ms. */
	readonly redirectDelayMs?: number;
	/**
	 * Optional logger for warning when an RP's frontchannelLogoutUri is refused
	 * or its iframe must be skipped. Falls back to `console` when omitted.
	 */
	readonly logger?: Logger;
}

const HTML_ESCAPE: Record<string, string> = {
	"&": "&amp;",
	"<": "&lt;",
	">": "&gt;",
	'"': "&quot;",
	"'": "&#39;",
};

function escapeHtml(s: string): string {
	return s.replace(/[&<>"']/g, (c) => HTML_ESCAPE[c] ?? c);
}

const DEFAULT_REDIRECT_DELAY_MS = 2_000;

/**
 * The redirect script, the same text on every page: it reads the target and
 * the delay from its own `data-` attributes, so the policy allows it by one
 * fixed hash and no value is ever written into script context.
 */
const REDIRECT_SCRIPT =
	"(function(s){setTimeout(function(){window.location.href=s.dataset.target;},Number(s.dataset.delay));})(document.currentScript);";
const REDIRECT_SCRIPT_SOURCE = `'sha256-${createHash("sha256").update(REDIRECT_SCRIPT, "utf8").digest("base64")}'`;

/**
 * An http(s) origin a CSP host-source can name exactly: dot-separated labels
 * of letters, digits and `-`, one optional terminal dot (CSP's host-part
 * allows it), and an optional port. Anything else (an IPv6 literal, `_`, `;`)
 * could not be listed, or could break the policy.
 */
const SOURCE_EXPRESSION_ORIGIN = /^https?:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?(?::[0-9]+)?$/;

/**
 * The page's own policy: nothing but frames from `frameOrigins`, and the
 * redirect script when the page has it.
 */
function pagePolicy(frameOrigins: ReadonlySet<string>, redirect: boolean): string {
	const directives = [
		"default-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	];
	// Each frame's own origin. An `http:` source also matches the same host's
	// `https:` (CSP's secure upgrade): the same relying party, so kept rather
	// than dropping http front-channel URIs.
	if (frameOrigins.size > 0) directives.push(`frame-src ${[...frameOrigins].join(" ")}`);
	if (redirect) directives.push(`script-src ${REDIRECT_SCRIPT_SOURCE}`);
	return directives.join("; ");
}

/**
 * `baseUri` with `iss` (and optionally `sid`) set as query parameters,
 * through `URL` so an existing query is kept and a fragment stays last (RFC
 * 3986 §3.5) instead of swallowing the new parameters.
 */
function buildIframeUrl(baseUri: string, issuer: string, sid: string | undefined): string {
	const url = new URL(baseUri);
	url.searchParams.set("iss", issuer);
	if (sid !== undefined) {
		url.searchParams.set("sid", sid);
	}
	return url.toString();
}

/** Why the page's redirect was dropped. */
type PostLogoutRedirectRefusal =
	| RedirectUriRejection["reason"]
	| "not-an-object"
	| "not-a-string"
	| "state-not-a-string"
	| "unreadable";

/**
 * Where the page's script sends the browser: `opts.postLogoutRedirect.uri`
 * when core's `checkRedirectUri` accepts it as written, with a non-empty
 * `state` appended through `URLSearchParams`; otherwise `undefined`. Absent
 * (no redirect, or an empty `uri`) is silent; a refusal is one warn with the
 * reason, never the value. Every read and the warn are guarded, so this
 * never throws.
 */
function postLogoutRedirectTarget(
	opts: RenderFrontchannelLogoutHtmlOptions,
	logger: Pick<Logger, "warn">,
): string | undefined {
	const refuse = (reason: PostLogoutRedirectRefusal): undefined => {
		try {
			logger.warn({ reason }, "logout_frontchannel_redirect_refused");
		} catch {
			// A logger that throws costs the line, never the page.
		}
		return undefined;
	};
	// Each read once, through core's `guardedRead`: `null` is a read that
	// threw, never logged since its message could carry the value.
	const redirectRead = guardedRead(opts, "postLogoutRedirect");
	if (redirectRead === null) return refuse("unreadable");
	const redirect = redirectRead.value;
	if (redirect === undefined || redirect === null) return undefined;
	// A joined URI string from a caller written for the earlier shape.
	if (typeof redirect !== "object") return refuse("not-an-object");
	const uriRead = guardedRead(redirect, "uri");
	const stateRead = guardedRead(redirect, "state");
	if (uriRead === null || stateRead === null) return refuse("unreadable");
	const [uri, state] = [uriRead.value, stateRead.value];
	if (uri === undefined || uri === null || uri === "") return undefined;
	if (typeof uri !== "string") return refuse("not-a-string");
	if (state !== undefined && typeof state !== "string") return refuse("state-not-a-string");
	const rejection = checkRedirectUri(uri);
	if (rejection !== null) return refuse(rejection.reason);
	// The base passed, so it parses; `searchParams` changes only the query.
	const target = new URL(uri);
	if (state !== undefined && state.length > 0) target.searchParams.set("state", state);
	return target.toString();
}

/** The front-channel logout page and the one policy it must be sent under. */
export interface FrontchannelLogoutPage {
	/** Sent as `Content-Type: text/html; charset=utf-8`. */
	readonly html: string;
	/**
	 * The page's `Content-Security-Policy`, sent as the response's only one: it
	 * allows frames from exactly the origins the page frames and the page's own
	 * redirect script by hash, and nothing else. A second policy on the same
	 * response would be enforced too and could block both.
	 */
	readonly contentSecurityPolicy: string;
}

/**
 * Renders an OIDC Front-Channel Logout 1.0 page: one hidden `<iframe>` per RP
 * with an http(s) `frontchannelLogoutUri` (any other is skipped with a warn),
 * its URL carrying `iss` and, unless `frontchannelLogoutSessionRequired` is
 * `false`, `sid`. With a `postLogoutRedirect` whose `uri` core's
 * `checkRedirectUri` accepts (any other is dropped with a warn), a static
 * `<script>` redirects, with the RP's `state`, after `redirectDelayMs` so the
 * iframes can load. Returned with the policy that allows exactly that; an RP
 * whose origin a CSP source expression cannot name is skipped with a warn.
 * Pure. Internal: the logout route serves it.
 */
export function renderFrontchannelLogoutPage(
	opts: RenderFrontchannelLogoutHtmlOptions,
): FrontchannelLogoutPage {
	return renderPage(opts, true);
}

/**
 * The page. `framesNamedByPolicy`: render only the frames whose origin the
 * returned policy can name, as the page served with it must.
 */
function renderPage(
	opts: RenderFrontchannelLogoutHtmlOptions,
	framesNamedByPolicy: boolean,
): FrontchannelLogoutPage {
	const logger = opts.logger ?? console;
	const frameOrigins = new Set<string>();
	const iframes = opts.rps
		.flatMap((entry) => {
			// http(s) only, whoever calls this: a registry entry made before the
			// code exchange checked it, or by a custom registry, is checked here.
			// Each field is read once; the iframe is built from what was read.
			const rp = usableFrontchannelRP(entry, "logout", logger);
			if (rp === undefined) return [];
			// A failure building the iframe URL skips that RP's iframe: throwing
			// after the session has closed would answer a 500
			// with an empty body.
			let iframeSrc: string;
			try {
				const includeSid = rp.frontchannelLogoutSessionRequired !== false;
				iframeSrc = buildIframeUrl(
					rp.frontchannelLogoutUri,
					opts.issuer,
					includeSid ? opts.sid : undefined,
				);
			} catch (err) {
				logger.warn(
					{ clientId: auditErrorText(rp.clientId), err: loggableError(err) },
					"logout_frontchannel_iframe_skipped",
				);
				return [];
			}
			// A frame the page's policy could not allow is not rendered.
			const origin = new URL(iframeSrc).origin;
			if (framesNamedByPolicy && !SOURCE_EXPRESSION_ORIGIN.test(origin)) {
				try {
					logger.warn(
						{ clientId: auditErrorText(rp.clientId), reason: "origin-not-a-source-expression" },
						"logout_frontchannel_iframe_skipped",
					);
				} catch {
					// A logger that throws costs the line, never the page.
				}
				return [];
			}
			frameOrigins.add(origin);
			// `URL` encodes for URL context; the HTML attribute still needs `&amp;`.
			// `hidden`, not a style attribute: the page's policy allows no style.
			return [
				`<iframe src="${escapeHtml(iframeSrc)}" hidden aria-hidden="true" referrerpolicy="no-referrer"></iframe>`,
			];
		})
		.join("\n    ");

	// Read by the script as a number, so only a non-negative whole number is written.
	const requestedDelay = opts.redirectDelayMs;
	const delay =
		Number.isFinite(requestedDelay) && (requestedDelay as number) >= 0
			? Math.trunc(requestedDelay as number)
			: DEFAULT_REDIRECT_DELAY_MS;
	const redirectTarget = postLogoutRedirectTarget(opts, logger);
	const redirect =
		redirectTarget !== undefined
			? `<script data-target="${escapeHtml(redirectTarget)}" data-delay="${delay}">${REDIRECT_SCRIPT}</script>`
			: "";

	const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Signing out…</title></head>
<body>
  <p>Signing you out…</p>
  ${iframes}
  ${redirect}
</body>
</html>`;
	return {
		html,
		contentSecurityPolicy: pagePolicy(frameOrigins, redirectTarget !== undefined),
	};
}

/**
 * The page's markup alone, every http(s) RP framed. A caller that serves it
 * sends it under a policy of its own that allows the frames' origins and the
 * redirect script's hash.
 */
export function renderFrontchannelLogoutHtml(opts: RenderFrontchannelLogoutHtmlOptions): string {
	return renderPage(opts, false).html;
}
