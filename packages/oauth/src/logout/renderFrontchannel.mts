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
import { auditErrorText, loggableError } from "@o3co/auth-provider-core";
import { usableFrontchannelLogoutUri } from "./frontchannelLogoutUri.mjs";

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
	 * Where the page sends the browser once the iframes have had their time:
	 * the validated `post_logout_redirect_uri` with the RP's `state` already
	 * on it, exactly as the route's own redirect would carry it. Taken as
	 * given; the caller composes it.
	 */
	readonly postLogoutRedirectUri?: string;
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

/**
 * `JSON.stringify`, then `<` and `>` escaped as `\u003c` / `\u003e`, so an
 * embedded `</script>` cannot close the inline `<script>` block (OWASP "JSON
 * in HTML"). `JSON.stringify` alone leaves `<` and `>` literal.
 */
function safeJsStringLiteral(s: string): string {
	return JSON.stringify(s).replace(/</g, "\\u003c").replace(/>/g, "\\u003e");
}

const DEFAULT_REDIRECT_DELAY_MS = 2_000;

/**
 * `baseUri` with `iss` (and optionally `sid`) set as query parameters,
 * through `URL` so an existing query is kept.
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
 * Renders an OIDC Front-Channel Logout 1.0 page: one hidden `<iframe>` per RP
 * with a `frontchannelLogoutUri` core's `checkRedirectUri` accepts (any other
 * is skipped with a warn), its URL carrying `iss` and, unless
 * `frontchannelLogoutSessionRequired` is `false`, `sid`. With
 * `postLogoutRedirectUri`, a `<script>` redirects after `redirectDelayMs` so
 * the iframes can load. Pure; callers MUST send it as
 * `Content-Type: text/html; charset=utf-8`.
 */
export function renderFrontchannelLogoutHtml(opts: RenderFrontchannelLogoutHtmlOptions): string {
	const logger = opts.logger ?? console;
	const iframes = opts.rps
		.flatMap((rp) => {
			// Read once and guarded: it is only ever logged.
			let clientId: unknown;
			try {
				clientId = rp.clientId;
			} catch {
				clientId = undefined;
			}
			// Held to the redirect-URI rules: a registry entry made before the
			// code exchange checked it, or by a custom registry, is checked here.
			const uri = usableFrontchannelLogoutUri(
				() => rp.frontchannelLogoutUri,
				{ site: "logout", clientId },
				logger,
			);
			if (uri === undefined) return [];
			// A failure building the iframe URL skips that RP's iframe: throwing
			// after cascadeLogout has cleared session state would answer a 500
			// with an empty body.
			try {
				const includeSid = rp.frontchannelLogoutSessionRequired !== false;
				const iframeSrc = buildIframeUrl(uri, opts.issuer, includeSid ? opts.sid : undefined);
				// `URL` encodes for URL context; the HTML attribute still needs `&amp;`.
				return [
					`<iframe src="${escapeHtml(iframeSrc)}" style="display:none" aria-hidden="true" referrerpolicy="no-referrer"></iframe>`,
				];
			} catch (err) {
				logger.warn(
					{ clientId: auditErrorText(clientId), err: loggableError(err) },
					"logout_frontchannel_iframe_skipped",
				);
				return [];
			}
		})
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
