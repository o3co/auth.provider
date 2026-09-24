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
 * policy returned. `errorEnvelope` does not apply it; the callers that write
 * such text do.
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

/**
 * Whether `value` is a well-formed RFC 6749 error code: a non-empty string of
 * `NQSCHAR`s (Appendix A.7). A code from outside this provider's own source —
 * a grant policy's deny — is checked with it before it goes out as `error`.
 */
export function isWellFormedErrorCode(value: unknown): value is string {
	return typeof value === "string" && value.length > 0 && !OUTSIDE_NQSCHAR.test(value);
}

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
 * Contract scope: the three RFC 6749 §5.2 stock fields only (`error`,
 * `error_description`, `error_uri`). Extension fields (e.g. namespaced
 * sub-codes, rate-limit details) are not added here — pass through a
 * separate helper or a literal envelope object.
 *
 * @param error       Machine-readable error code (snake_case, e.g. `invalid_grant`).
 * @param description Optional human-readable detail. Empty string is dropped.
 * @param uri         Optional reference URL. Empty string is dropped.
 */
export function errorEnvelope(error: string, description?: string, uri?: string): ErrorEnvelope {
	return {
		error,
		...(description !== undefined && description !== "" ? { error_description: description } : {}),
		...(uri !== undefined && uri !== "" ? { error_uri: uri } : {}),
	};
}
