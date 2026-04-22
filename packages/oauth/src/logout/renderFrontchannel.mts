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

import type { Logger } from "@o3co/auth-provider-core";

export interface FrontchannelRP {
	readonly clientId: string;
	readonly frontchannelLogoutUri?: string;
	/** Defaults to `true` — append sid so RPs can correlate sessions. */
	readonly frontchannelLogoutSessionRequired?: boolean;
}

export interface RenderFrontchannelLogoutHtmlOptions {
	readonly rps: ReadonlyArray<FrontchannelRP>;
	readonly issuer: string;
	readonly sid: string;
	readonly postLogoutRedirectUri?: string;
	/** Defaults to 2000ms. */
	readonly redirectDelayMs?: number;
	/**
	 * Optional logger for warning when an RP's frontchannelLogoutUri is invalid
	 * and its iframe must be skipped. Falls back to `console` when omitted.
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

/**
 * JSON-stringifies a string, then escapes `<` and `>` as `\u003c` / `\u003e` so
 * an embedded `</script>` cannot prematurely close an inline `<script>` block.
 *
 * This is the standard CSP-safe pattern for embedding untrusted strings in
 * inline JS — see OWASP "JSON in HTML" guidance. Plain `JSON.stringify` alone
 * is not sufficient: it escapes `"`, but leaves `<` and `>` literal, which
 * allows `</script><script>alert(1)</script>` to break out of the inline JS
 * context even though the payload would otherwise be bound as a safe string.
 */
function safeJsStringLiteral(s: string): string {
	return JSON.stringify(s).replace(/</g, "\\u003c").replace(/>/g, "\\u003e");
}

const DEFAULT_REDIRECT_DELAY_MS = 2_000;

/**
 * Builds an iframe src URL by appending `iss` (and optionally `sid`) query
 * parameters to `baseUri`. Uses `new URL()` + `searchParams.set()` so that:
 *  - Existing query params are preserved with `&` separator.
 *  - Fragment identifiers remain at the end of the URL (RFC 3986 §3.5), so
 *    query params are not swallowed as fragment content by the browser.
 */
function buildIframeUrl(baseUri: string, issuer: string, sid: string | undefined): string {
	const url = new URL(baseUri);
	url.searchParams.set("iss", issuer);
	if (sid !== undefined) {
		url.searchParams.set("sid", sid);
	}
	return url.toString();
}

/**
 * Renders an OIDC Front-Channel Logout 1.0 HTML page: one hidden `<iframe>` per RP
 * that has a `frontchannelLogoutUri`. Each iframe URL carries `iss` and optionally
 * `sid` query parameters (sid included when `frontchannelLogoutSessionRequired`
 * is not explicitly `false`). When `postLogoutRedirectUri` is provided, appends
 * a `<script>` that redirects after `redirectDelayMs` to let iframes load.
 *
 * Pure function: does no I/O, returns a string. Callers MUST send with
 * `Content-Type: text/html; charset=utf-8`.
 */
export function renderFrontchannelLogoutHtml(opts: RenderFrontchannelLogoutHtmlOptions): string {
	const logger = opts.logger ?? console;
	const iframes = opts.rps
		.filter(
			(rp): rp is FrontchannelRP & { frontchannelLogoutUri: string } =>
				typeof rp.frontchannelLogoutUri === "string" && rp.frontchannelLogoutUri.length > 0,
		)
		.map((rp) => {
			// Use new URL() + searchParams to correctly handle URIs that contain an
			// existing query string or a fragment. Manual string-concat would produce
			// `https://rp/fc#frag?iss=...` where the browser treats the query as
			// part of the fragment — the RP never receives iss/sid.
			//
			// Per-RP try/catch: if new URL() throws (invalid or relative URI that slipped
			// past schema validation, or corrupted store record), skip that RP's iframe
			// rather than propagating the throw after cascadeLogout has already cleared
			// session state (which would produce a 500 with an empty response body).
			try {
				const includeSid = rp.frontchannelLogoutSessionRequired !== false;
				const iframeSrc = buildIframeUrl(
					rp.frontchannelLogoutUri,
					opts.issuer,
					includeSid ? opts.sid : undefined,
				);
				// escapeHtml is still required: new URL() percent-encodes for URL context
				// but the value is being placed inside an HTML attribute, so & must become
				// &amp; to produce well-formed HTML.
				return `<iframe src="${escapeHtml(iframeSrc)}" style="display:none" aria-hidden="true" referrerpolicy="no-referrer"></iframe>`;
			} catch (err) {
				logger.warn(
					`renderFrontchannelLogoutHtml: failed to build iframe for RP ${rp.clientId} (skipping):`,
					err,
				);
				return ""; // skipped; filtered out below
			}
		})
		.filter((s) => s.length > 0)
		.join("\n    ");

	const delay = opts.redirectDelayMs ?? DEFAULT_REDIRECT_DELAY_MS;
	const redirect = opts.postLogoutRedirectUri
		? `<script>setTimeout(() => { window.location.href = ${safeJsStringLiteral(opts.postLogoutRedirectUri)}; }, ${delay});</script>`
		: "";

	return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Signing out…</title></head>
<body>
  <p>Signing you out…</p>
  ${iframes}
  ${redirect}
</body>
</html>`;
}
