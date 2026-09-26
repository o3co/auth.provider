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

import { consoleLogger } from "../logging/consoleLogger.mjs";

/**
 * The characters RFC 6749 allows in error text. Appendix A.7 and A.8 define
 * `error` and `error_description` alike as `1*NQSCHAR`, with
 * `NQSCHAR = %x20-21 / %x23-5B / %x5D-7E`: printable ASCII without `"` and
 * `\` (§5.2, and §4.1.2.1 for the authorization endpoint's error redirect).
 * This is the one statement of that class; a drift guard keeps it here.
 */
const OUTSIDE_NQSCHAR = /[^\x20-\x21\x23-\x5B\x5D-\x7E]/u;
const EVERY_OUTSIDE_NQSCHAR = new RegExp(OUTSIDE_NQSCHAR.source, "gu");

/**
 * `text` with every character RFC 6749 does not allow in error text replaced
 * by `?`, one per code point.
 *
 * For text a response carries that its author does not fully control: a
 * description quoting what the client sent (a grant type, a scope, an
 * audience, a token type), a configured value, or a description a grant
 * policy returned. {@link errorEnvelope} applies it to every description it
 * builds; a writer that builds its body itself — a redirect's query, a literal
 * `{ error, error_description }` — applies it to the text it echoes.
 *
 * A value that is not a string — a JavaScript policy can return anything —
 * answers `undefined` rather than being coerced, so the caller falls back to
 * its own default. The overloads keep a caller that passes a string typed
 * `string`.
 */
export function sanitizeErrorText(text: string): string;
export function sanitizeErrorText(text: unknown): string | undefined;
export function sanitizeErrorText(text: unknown): string | undefined {
	return typeof text === "string" ? text.replace(EVERY_OUTSIDE_NQSCHAR, "?") : undefined;
}

/** The longest error text {@link auditErrorText} keeps. */
const AUDITED_ERROR_TEXT_MAX_LENGTH = 200;

/**
 * Error text as a log line or an audit event records it: sanitised
 * ({@link sanitizeErrorText}) and capped at 200 characters, the cut marked
 * with `...`. For text a client or a policy chose — an echoed grant type, a
 * refusal's description, a malformed code — so neither can put unbounded
 * text there. A non-string answers `undefined`.
 */
export function auditErrorText(text: string): string;
export function auditErrorText(text: unknown): string | undefined;
export function auditErrorText(text: unknown): string | undefined {
	const sanitised = sanitizeErrorText(text);
	if (sanitised === undefined || sanitised.length <= AUDITED_ERROR_TEXT_MAX_LENGTH)
		return sanitised;
	return `${sanitised.slice(0, AUDITED_ERROR_TEXT_MAX_LENGTH - 3)}...`;
}

/** How many entries {@link auditErrorList} keeps unless told otherwise. */
const AUDITED_LIST_MAX_ITEMS = 10;

/**
 * A list a client or a peer chose — the scopes it asked for, the resources it
 * named — as a log line or an audit event records it: still a list, so a query
 * that reads the field as one keeps working, with each entry through
 * {@link auditErrorText} (sanitised, capped at 200 characters) and only the
 * first `maxItems` kept (10 by default). A small, well-formed list comes back
 * as it was. The caller that logs it adds how many entries there were when
 * the list was cut (`kept.length < values.length`), so the line says so.
 *
 * `maxItems` must be a positive integer; anything else is a RangeError.
 */
export function auditErrorList(
	values: readonly string[],
	maxItems: number = AUDITED_LIST_MAX_ITEMS,
): string[] {
	if (!Number.isInteger(maxItems) || maxItems < 1) {
		throw new RangeError(`auditErrorList: maxItems must be a positive integer (got ${maxItems})`);
	}
	return values.slice(0, maxItems).map((value) => auditErrorText(value));
}

/**
 * Whether `value` is a well-formed RFC 6749 error code: a non-empty string of
 * `NQSCHAR`s (Appendix A.7). A code from outside this provider's own source —
 * a grant policy's deny — is checked with it before it goes out as `error`.
 */
export function isWellFormedErrorCode(value: unknown): value is string {
	return typeof value === "string" && value.length > 0 && !OUTSIDE_NQSCHAR.test(value);
}

/**
 * RFC 3986's grammar for a URI-reference, piece by piece. Every character it
 * admits is inside the set RFC 6749 §5.2 allows `error_uri`
 * (`%x21 / %x23-5B / %x5D-7E`), so a reference that parses keeps to both.
 */
const PCT = "%[0-9A-Fa-f]{2}";
const UNRESERVED_SUB_DELIMS = "A-Za-z0-9\\-._~!$&'()*+,;=";
/** Appendix B: scheme, authority, path, query, fragment. Every string matches. */
const URI_REFERENCE_PARTS = /^(?:([^:/?#]+):)?(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/;
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;
/** `*( pchar / "/" )`, what a path is written in. */
const PATH = new RegExp(`^(?:[${UNRESERVED_SUB_DELIMS}:@/]|${PCT})*$`);
/** `*( pchar / "/" / "?" )`, what a query and a fragment are written in. */
const QUERY_OR_FRAGMENT = new RegExp(`^(?:[${UNRESERVED_SUB_DELIMS}:@/?]|${PCT})*$`);
/** A host: an IP literal in brackets (IPv6, or IPv4 inside it), or a reg-name. */
const HOST = new RegExp(`^(?:\\[[0-9A-Fa-f:.]+\\]|(?:[${UNRESERVED_SUB_DELIMS}]|${PCT})*)$`);
const PORT = /^[0-9]*$/;

/** The schemes an `error_uri` may name: §5.2's "human-readable web page". */
const WEB_SCHEMES: ReadonlySet<string> = new Set(["http", "https"]);

/** Resolves a relative reference so the WHATWG parser can judge the whole. */
const URI_REFERENCE_BASE = "https://error-uri.invalid/";

/**
 * Whether `authority` is `host [ ":" port ]` (RFC 3986 §3.2) — with no
 * userinfo. A link to a web page names no user, and a userinfo is how a
 * reference disguises its host (`https://example.com@evil.example/` goes to
 * evil.example); §3.2.1 deprecates `user:password` besides.
 */
function isAuthority(authority: string): boolean {
	if (authority.includes("@")) return false;
	const portAt = authority.startsWith("[")
		? authority.indexOf(":", authority.indexOf("]"))
		: authority.lastIndexOf(":");
	const host = portAt === -1 ? authority : authority.slice(0, portAt);
	const port = portAt === -1 ? "" : authority.slice(portAt + 1);
	return HOST.test(host) && PORT.test(port);
}

/**
 * Whether `value` is an `error_uri` RFC 6749 allows (§5.2, Appendix A.9):
 *
 * - a URI-reference by RFC 3986's grammar — each component in its own
 *   characters, brackets only around an IP-literal host, no userinfo, at
 *   most one fragment, and a relative path whose first segment has no colon;
 * - absolute only as `http:` or `https:` — §5.2's "human-readable web page",
 *   so no `javascript:`, `data:`, `vbscript:` or `file:`;
 * - and one the WHATWG URL parser resolves, which refuses what the grammar
 *   alone admits: an IPv6 literal that is not one, a port past 65535.
 */
function isWellFormedErrorUri(value: unknown): value is string {
	if (typeof value !== "string") return false;
	const parts = URI_REFERENCE_PARTS.exec(value);
	if (parts === null) return false;
	const [, scheme, authority, path = "", query = "", fragment = ""] = parts;
	if (scheme !== undefined && !(SCHEME.test(scheme) && WEB_SCHEMES.has(scheme.toLowerCase()))) {
		return false;
	}
	if (authority !== undefined && !isAuthority(authority)) return false;
	if (!PATH.test(path) || !QUERY_OR_FRAGMENT.test(query) || !QUERY_OR_FRAGMENT.test(fragment)) {
		return false;
	}
	// path-noscheme (RFC 3986 §4.2): a relative path's first segment reads as
	// a scheme if it holds a colon.
	if (scheme === undefined && authority === undefined && path.split("/")[0]?.includes(":")) {
		return false;
	}
	try {
		new URL(value, URI_REFERENCE_BASE);
		return true;
	} catch {
		return false;
	}
}

/**
 * The code {@link errorEnvelope} sends in place of a malformed one. The code
 * came from server-side code — a caller, a contributed mechanism, a module —
 * never from the client, so the fault is the server's; and the envelope does
 * not know the status its caller answers with, so it sends the one code that
 * is true whatever that status is.
 */
const MALFORMED_CODE_FALLBACK = "server_error";

/**
 * RFC 6749 §5.2 error response envelope. Used across `/oauth/*` and the
 * session router so consumer code can parse error responses with a single
 * shape regardless of which surface produced them.
 */
export interface ErrorEnvelope {
	readonly error: string;
	readonly error_description?: string;
	readonly error_uri?: string;
}

/**
 * Construct an RFC 6749 §5.2 error envelope. Optional fields are omitted
 * (rather than serialized as `undefined`) so JSON consumers see a clean
 * shape — `JSON.stringify({ x: undefined })` does drop the key, but having
 * the helper pre-omit keeps the in-memory object consistent for tests
 * that snapshot the structure with `toEqual`.
 *
 * Empty-string `description` / `uri` are treated as omissions: RFC 6749
 * §5.2 specifies these as optional human-readable / URI fields, and an
 * empty string conveys no information while still serializing as a
 * present-but-empty value. Callers that need an explicit empty string
 * should construct the envelope literal directly.
 *
 * The text keeps to RFC 6749's characters (Appendix A.7, A.8), so every
 * writer that goes through here conforms whatever it was handed — a
 * mechanism's retry instruction, a limiter adapter's reason, a configured
 * name:
 *
 * - `description` is sanitised ({@link sanitizeErrorText}): a character
 *   outside `1*NQSCHAR` is sent as `?`. One that is not a string — a
 *   JavaScript caller can pass anything — is dropped like an empty one,
 *   never coerced.
 * - `error` must be well-formed ({@link isWellFormedErrorCode}). A malformed
 *   code is sent as `server_error` and logged through `consoleLogger` as
 *   `error_envelope_code_malformed`, sanitised and capped. A caller that
 *   builds a code from something it does not control, and knows its answer
 *   is a refusal of the client's request, checks the code itself and falls
 *   back to a client-error code (the token-binding middleware does).
 * - `uri` is sent only when it is an http(s) web page or a relative reference
 *   that RFC 3986's grammar parses, in RFC 6749's `error_uri` characters (§5.2,
 *   Appendix A.9). Any other is dropped — a reference with a character
 *   replaced would point somewhere else — and logged as
 *   `error_envelope_uri_malformed`.
 *
 * Contract scope: the three RFC 6749 §5.2 stock fields only (`error`,
 * `error_description`, `error_uri`). Extension fields (e.g. namespaced
 * sub-codes, rate-limit details) are not added here — pass through a
 * separate helper or a literal envelope object.
 *
 * @param error       Machine-readable error code (snake_case, e.g. `invalid_grant`).
 * @param description Optional human-readable detail. Empty string is dropped.
 * @param uri         Optional reference URL. Empty string is dropped, and so is one RFC 6749 does not allow.
 */
export function errorEnvelope(error: string, description?: string, uri?: string): ErrorEnvelope {
	const text = sanitizeErrorText(description);
	const reference = uri === undefined || uri === "" ? undefined : wellFormedUriOrNothing(uri);
	return {
		error: wellFormedCodeOrFallback(error),
		...(text !== undefined && text !== "" ? { error_description: text } : {}),
		...(reference !== undefined ? { error_uri: reference } : {}),
	};
}

/** `uri` when RFC 6749 allows it as `error_uri`; otherwise nothing, logged. */
function wellFormedUriOrNothing(uri: unknown): string | undefined {
	if (isWellFormedErrorUri(uri)) return uri;
	consoleLogger.warn(
		{ error_uri: auditErrorText(uri) ?? `(${typeof uri})` },
		"error_envelope_uri_malformed",
	);
	return undefined;
}

/** `error` when it is a well-formed RFC 6749 code, otherwise the logged fallback. */
function wellFormedCodeOrFallback(error: unknown): string {
	if (isWellFormedErrorCode(error)) return error;
	consoleLogger.warn(
		{ error: auditErrorText(error) ?? `(${typeof error})` },
		"error_envelope_code_malformed",
	);
	return MALFORMED_CODE_FALLBACK;
}
