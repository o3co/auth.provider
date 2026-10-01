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

import type { Logger, RedirectUriRejection } from "@o3co/auth-provider-core";
import { auditErrorText, checkRedirectUri, loggableError } from "@o3co/auth-provider-core";
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
	 * on it, exactly as the route's own redirect would carry it. Checked here
	 * with core's `checkRedirectUri`, the rule the route accepts it by, with
	 * a trailing `state` pair as `URLSearchParams` writes it set aside: a value
	 * the check refuses, one that is not a string, or a read that throws
	 * leaves the page without its redirect, logged once at warn as
	 * `logout_frontchannel_redirect_refused` with the reason, never the URI.
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
type PostLogoutRedirectRefusal = RedirectUriRejection["reason"] | "not-a-string" | "unreadable";

/**
 * A trailing `state` pair as `URLSearchParams` writes it, the way the logout
 * route appends the RP's `state` to a registered URI: `?` or `&`, then
 * `state=`, then only what form encoding emits (letters, digits, `*-._`, `%`
 * escapes and `+`). It is last: a registered URI has no fragment and no
 * `state` of its own.
 */
const APPENDED_STATE = /[?&]state=[A-Za-z0-9*._%+-]*$/;

/**
 * `raw` with the `state` pair the caller appends set aside, when it is
 * exactly that pair; otherwise `raw` itself. The rest is kept byte for byte,
 * and anything else in the query, another `state` included, stays for the
 * check to judge.
 */
function withoutAppendedState(raw: string): string {
	const appended = APPENDED_STATE.exec(raw);
	if (appended === null) return raw;
	const rest = raw.slice(0, appended.index);
	// An empty pair left behind is the check's to refuse, so keep it in view.
	return rest.endsWith("?") || rest.endsWith("&") ? raw : rest;
}

/**
 * `opts.postLogoutRedirectUri` when core's `checkRedirectUri` accepts it with
 * its appended `state` set aside; otherwise `undefined`. Absent is silent; a
 * refusal is one warn with the reason, never the value. The option's read and
 * the warn are guarded, so this never throws.
 */
function checkedPostLogoutRedirectUri(
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
	let value: unknown;
	try {
		value = opts.postLogoutRedirectUri;
	} catch {
		// The error is not logged: its message could carry the value.
		return refuse("unreadable");
	}
	if (value === undefined || value === null || value === "") return undefined;
	if (typeof value !== "string") return refuse("not-a-string");
	const rejection = checkRedirectUri(withoutAppendedState(value));
	return rejection === null ? value : refuse(rejection.reason);
}

/**
 * Renders an OIDC Front-Channel Logout 1.0 page: one hidden `<iframe>` per RP
 * with an http(s) `frontchannelLogoutUri` (any other is skipped with a warn),
 * its URL carrying `iss` and, unless `frontchannelLogoutSessionRequired` is
 * `false`, `sid`. With a `postLogoutRedirectUri` core's `checkRedirectUri`
 * accepts (any other is dropped with a warn), a `<script>` redirects after
 * `redirectDelayMs` so the iframes can load. Pure; callers MUST send it as
 * `Content-Type: text/html; charset=utf-8`.
 */
export function renderFrontchannelLogoutHtml(opts: RenderFrontchannelLogoutHtmlOptions): string {
	const logger = opts.logger ?? console;
	const iframes = opts.rps
		.flatMap((rp) => {
			// http(s) only, whoever calls this: a registry entry made before the
			// code exchange checked it, or by a custom registry, is checked here.
			const uri = usableFrontchannelLogoutUri(rp, "logout", logger);
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
				// Read here only, and guarded: it is only logged.
				let clientId: unknown;
				try {
					clientId = rp.clientId;
				} catch {
					clientId = undefined;
				}
				logger.warn(
					{ clientId: auditErrorText(clientId), err: loggableError(err) },
					"logout_frontchannel_iframe_skipped",
				);
				return [];
			}
		})
		.join("\n    ");

	// Written into the script as a number literal, so only a non-negative
	// whole number reaches it.
	const requestedDelay = opts.redirectDelayMs;
	const delay =
		Number.isFinite(requestedDelay) && (requestedDelay as number) >= 0
			? Math.trunc(requestedDelay as number)
			: DEFAULT_REDIRECT_DELAY_MS;
	const redirectTarget = checkedPostLogoutRedirectUri(opts, logger);
	const redirect =
		redirectTarget !== undefined
			? `<script>setTimeout(() => { window.location.href = ${safeJsStringLiteral(redirectTarget)}; }, ${delay});</script>`
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
