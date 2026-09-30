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
 * A deliberately small HTTP client for fetching revocation material (a CRL by
 * GET, an OCSP request by POST per RFC 6960 Appendix A.1), with the limits
 * that make fetching a URL taken from a certificate safe at all.
 *
 * Such a URL is a server-side request forgery sink: the request itself is
 * the payload (a distribution point of `http://169.254.169.254/...` needs no
 * parseable answer). Two layered controls bound it:
 * 1. Only a validated path may cause a fetch: `validate.mts` completes path
 *    validation before reading any URL, so it always comes from a
 *    certificate chaining to a configured trust anchor.
 * 2. A required host allowlist, enforced here: trusting a CA to issue
 *    certificates is not trusting it to choose destinations inside the
 *    operator's network (the separation `mtls.trustedProxies` draws).
 *
 * Since the operator names every destination, and internal CAs usually live
 * at private addresses, core's `isSpecialUseAddress` (RFC 6890) is not
 * consulted here; see `core/src/net/special-use.mts`.
 *
 * On top of those: redirects are refused (a second, unvetted destination),
 * the body is capped while it is read, a wall-clock timeout applies, and no
 * credentials are sent. The platform `fetch` defaults — follow redirects, no
 * size limit, no allowlist — all fail open, hence a bespoke client.
 *
 * A refusal is a `FetchRejection` plus a `detail` in this module's own words.
 * A thrown platform error rides as `cause`; its message is never read or
 * copied into `detail`.
 */

/** Why a fetch did not produce bytes. Values are stable — audit logs read them. */
export type FetchRejection =
	| "scheme_not_allowed"
	| "host_not_allowed"
	| "url_unparseable"
	| "url_has_credentials"
	| "redirect_refused"
	| "http_error"
	| "response_too_large"
	| "unexpected_content_type"
	| "timeout"
	| "network_error";

/**
 * Refusals meaning the source did not deliver a usable answer (unreachable,
 * timed out, an HTTP error, a redirect, too large, the wrong type), as against
 * those about the URL a certificate names. They are faults of the source or
 * of this server's configuration, never a verdict on the certificate, and no
 * client can cause them. `crl.mts` and `ocsp.mts` read this to mark an
 * unavailability as an outage.
 */
const SOURCE_FAILURES: ReadonlySet<FetchRejection> = new Set<FetchRejection>([
	"timeout",
	"network_error",
	"http_error",
	"redirect_refused",
	"response_too_large",
	"unexpected_content_type",
]);

/** Whether a refusal is the source's failure rather than the URL's (see {@link SOURCE_FAILURES}). */
export const isSourceFailure = (reason: FetchRejection): boolean => SOURCE_FAILURES.has(reason);

export type FetchOutcome =
	| { readonly ok: true; readonly bytes: Uint8Array }
	| {
			readonly ok: false;
			readonly reason: FetchRejection;
			readonly detail: string;
			/** The platform fetch's error, when it threw one. */
			readonly cause?: unknown;
	  };

export interface GuardedFetchOptions {
	/**
	 * Hosts revocation material may be fetched from: `host` or `host:port`,
	 * matched case-insensitively; an entry without a port matches any port.
	 * An IPv6 literal may be bracketed (`[::1]`, `[::1]:8080`) or, without a
	 * port, bare, expanded or compressed. Never empty: that would mean "any
	 * destination", and the module refuses it at boot.
	 */
	readonly allowedHosts: readonly string[];
	readonly timeoutMs: number;
	readonly maxBytes: number;
	/** Injected in tests. Defaults to the global `fetch`. */
	readonly fetchImpl?: typeof globalThis.fetch;
}

/**
 * What to send. Omitted, the fetch is a plain GET for a CRL. An OCSP request
 * sets `method: "POST"` with the DER request as `body`, its `contentType`,
 * and the media type it expects back.
 */
export interface GuardedRequest {
	readonly method?: "GET" | "POST";
	readonly body?: Uint8Array;
	/** `Content-Type` of `body`. */
	readonly contentType?: string;
	/** `Accept` header. Defaults to the CRL media types. */
	readonly accept?: string;
	/**
	 * Media type the response must declare — compared case-insensitively and
	 * without parameters; anything else is `unexpected_content_type`. Omitted,
	 * the response's type is not checked: distribution points answer with
	 * `application/pkix-crl`, `application/octet-stream`, or nothing useful,
	 * and the bytes are what count.
	 */
	readonly expectContentType?: string;
}

export type GuardedFetch = (url: string, request?: GuardedRequest) => Promise<FetchOutcome>;

const CRL_ACCEPT = "application/pkix-crl, application/octet-stream, */*";

/** The media type of a `Content-Type` value, lower-cased, parameters dropped. */
const mediaTypeOf = (contentType: string | null): string | null => {
	if (contentType === null) return null;
	const media = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
	return media === "" ? null : media;
};

/**
 * The form both sides of the allowlist comparison are reduced to: lower-case,
 * and an IPv6 literal bracket-less in the WHATWG serialisation.
 * `URL.hostname` keeps the brackets and always compresses, while an entry may
 * be written either way, so the entry goes through `URL` too; a literal `URL`
 * rejects is kept as written, where it matches nothing.
 */
const canonicalHost = (host: string): string => {
	const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
	if (!bare.includes(":")) return bare.toLowerCase();
	try {
		return new URL(`http://[${bare}]/`).hostname.slice(1, -1);
	} catch {
		return bare.toLowerCase();
	}
};

/**
 * Parse an allowlist entry into its host and optional port.
 *
 * Bracketed IPv6 (`[::1]:8080`) is handled by locating the port after the
 * closing bracket, so an address's own colons are not read as a separator;
 * a bare literal (`::1`) has more than one colon and no brackets, and a port
 * cannot be attached to that form, so it is read as a host alone.
 */
const splitHostPort = (entry: string): { host: string; port: string | null } => {
	const trimmed = entry.trim().toLowerCase();
	if (trimmed.startsWith("[")) {
		const close = trimmed.indexOf("]");
		if (close === -1) return { host: canonicalHost(trimmed), port: null };
		const rest = trimmed.slice(close + 1);
		return {
			host: canonicalHost(trimmed.slice(1, close)),
			port: rest.startsWith(":") ? rest.slice(1) : null,
		};
	}
	const colon = trimmed.lastIndexOf(":");
	if (colon === -1 || trimmed.indexOf(":") !== colon) {
		return { host: canonicalHost(trimmed), port: null };
	}
	return { host: canonicalHost(trimmed.slice(0, colon)), port: trimmed.slice(colon + 1) };
};

/** A transport's error code: `ECONNREFUSED`, `ENOTFOUND`, `UND_ERR_SOCKET`. */
const TRANSPORT_CODE = /^[A-Z][A-Z0-9_]{1,63}$/;

/**
 * The transport's own name for a failure, from the first `code` on the
 * error's cause chain. undici — Node's `fetch` — reports every failure as
 * `TypeError("fetch failed")` with the code on `cause`. A code is a closed
 * vocabulary; the messages beside it are never read.
 */
const transportCodeOf = (err: unknown): string | undefined => {
	let current: unknown = err;
	for (let depth = 0; depth < 5 && typeof current === "object" && current !== null; depth++) {
		let code: unknown;
		let cause: unknown;
		try {
			code = (current as { code?: unknown }).code;
			cause = (current as { cause?: unknown }).cause;
		} catch {
			return undefined;
		}
		if (typeof code === "string" && TRANSPORT_CODE.test(code)) return code;
		current = cause;
	}
	return undefined;
};

/** The statuses that name another location (RFC 9110 §15.4); 304 names none. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/**
 * Read at most `maxBytes` from the body, aborting as soon as the cap is
 * passed.
 *
 * `Content-Length` is checked first as a cheap rejection, but it is a claim
 * made by the responder and is not relied on: a responder that lies, or omits
 * it under chunked encoding, is caught by the running total instead.
 */
const readCapped = async (
	response: Response,
	maxBytes: number,
): Promise<{ ok: true; bytes: Uint8Array } | { ok: false }> => {
	const declared = response.headers.get("content-length");
	if (declared !== null && Number(declared) > maxBytes) {
		// Refused before a reader is taken: release the body, or the
		// connection stays held until the peer gives up.
		await response.body?.cancel().catch(() => undefined);
		return { ok: false };
	}
	const body = response.body;
	if (body === null) return { ok: true, bytes: new Uint8Array(0) };

	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				await reader.cancel();
				return { ok: false };
			}
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}
	const bytes = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		bytes.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return { ok: true, bytes };
};

export const createGuardedFetch = (options: GuardedFetchOptions): GuardedFetch => {
	const fetchImpl = options.fetchImpl ?? globalThis.fetch;
	const allowed = options.allowedHosts.map(splitHostPort);

	const hostAllowed = (url: URL): boolean =>
		allowed.some((entry) => {
			if (entry.host !== canonicalHost(url.hostname)) return false;
			return entry.port === null || entry.port === (url.port === "" ? defaultPort(url) : url.port);
		});

	const defaultPort = (url: URL): string => (url.protocol === "https:" ? "443" : "80");

	return async (rawUrl: string, request: GuardedRequest = {}): Promise<FetchOutcome> => {
		let url: URL;
		try {
			url = new URL(rawUrl);
		} catch {
			return { ok: false, reason: "url_unparseable", detail: rawUrl };
		}

		// http is normal for CRL distribution points — a CRL is signed, so its
		// transport does not carry the trust — but nothing else is.
		if (url.protocol !== "http:" && url.protocol !== "https:") {
			return { ok: false, reason: "scheme_not_allowed", detail: url.protocol };
		}
		// Credentials in the URL would be sent by us to a destination a
		// certificate named. There is no legitimate CRL that needs them.
		if (url.username !== "" || url.password !== "") {
			return { ok: false, reason: "url_has_credentials", detail: url.host };
		}
		if (!hostAllowed(url)) {
			return { ok: false, reason: "host_not_allowed", detail: url.host };
		}

		const headers: Record<string, string> = { accept: request.accept ?? CRL_ACCEPT };
		if (request.contentType !== undefined) headers["content-type"] = request.contentType;

		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), options.timeoutMs);
		try {
			const response = await fetchImpl(url, {
				method: request.method ?? "GET",
				// A redirect names a second destination the allowlist never
				// vetted; following one makes an allowlisted host an open proxy.
				// "manual" hands it back unfollowed, refused by its status below.
				redirect: "manual",
				signal: controller.signal,
				credentials: "omit",
				headers,
				...(request.body === undefined
					? {}
					: { body: request.body as unknown as NonNullable<Parameters<typeof fetch>[1]>["body"] }),
			});
			if (REDIRECT_STATUSES.has(response.status) || response.type === "opaqueredirect") {
				await response.body?.cancel().catch(() => undefined);
				return {
					ok: false,
					reason: "redirect_refused",
					detail:
						response.type === "opaqueredirect" ? "opaque redirect" : `HTTP ${response.status}`,
				};
			}
			if (!response.ok) {
				// Refused before the body is read: release it, or the connection
				// stays held until the peer gives up.
				await response.body?.cancel().catch(() => undefined);
				return { ok: false, reason: "http_error", detail: `HTTP ${response.status}` };
			}
			if (request.expectContentType !== undefined) {
				// Checked before the body is read: a captive portal or an error
				// page answering 200 with HTML is "the responder did not answer
				// as a responder", and this is where that is named rather than
				// surfacing later as a parse failure.
				const declared = mediaTypeOf(response.headers.get("content-type"));
				if (declared !== request.expectContentType.toLowerCase()) {
					await response.body?.cancel().catch(() => undefined);
					return {
						ok: false,
						reason: "unexpected_content_type",
						detail: `expected ${request.expectContentType}, got ${declared ?? "no Content-Type"}`,
					};
				}
			}
			const body = await readCapped(response, options.maxBytes);
			if (!body.ok) {
				return {
					ok: false,
					reason: "response_too_large",
					detail: `exceeded ${options.maxBytes} bytes`,
				};
			}
			return { ok: true, bytes: body.bytes };
		} catch (err) {
			if (controller.signal.aborted) {
				return { ok: false, reason: "timeout", detail: `${options.timeoutMs}ms` };
			}
			return {
				ok: false,
				reason: "network_error",
				detail: transportCodeOf(err) ?? "fetch failed",
				cause: err,
			};
		} finally {
			clearTimeout(timer);
		}
	};
};
