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

/*
 * RFC 6749 `token_type`: whether a value is a token type at all (§A.13,
 * checked against RFC 3986's grammar) and whether it is Bearer (§5.1). Both
 * routes that hand an upstream token on ask these.
 */

import { isIPv6 } from "node:net";

/**
 * The one type an upstream access token may be handed on as, spelled as RFC
 * 6750 §2.1 spells the scheme. RFC 6749 §5.1 compares case-insensitively, so
 * this is the spelling to write, never to test against; use
 * {@link isBearerTokenType}.
 */
export const BEARER_TOKEN_TYPE = "Bearer";

// RFC 3986 Appendix A, as regular-expression source. Composed from the ABNF
// rule by rule so each piece can be checked against the RFC by name.
const UNRESERVED = "A-Za-z0-9\\-._~";
const SUB_DELIMS = "!$&'()*+,;=";
const PCT_ENCODED = "%[0-9A-Fa-f]{2}";
const PCHAR = `(?:[${UNRESERVED}${SUB_DELIMS}:@]|${PCT_ENCODED})`;
const SEGMENT = `${PCHAR}*`;
const SEGMENT_NZ = `${PCHAR}+`;
const SEGMENT_NZ_NC = `(?:[${UNRESERVED}${SUB_DELIMS}@]|${PCT_ENCODED})+`;
const QUERY_OR_FRAGMENT = `(?:${PCHAR}|[/?])*`;
const SCHEME = "[A-Za-z][A-Za-z0-9+\\-.]*";
const USERINFO = `(?:[${UNRESERVED}${SUB_DELIMS}:]|${PCT_ENCODED})*`;
const REG_NAME = `(?:[${UNRESERVED}${SUB_DELIMS}]|${PCT_ENCODED})*`;
// The IP-literal's brackets only; what is between them is checked below,
// because an IPv6 address is not a grammar a regular expression states well.
const IP_LITERAL = "\\[[^\\[\\]]*\\]";
// IPv4address needs no alternative of its own: lexically it is a reg-name,
// and RFC 3986 §3.2.2 reads a host that is not a valid one as a reg-name.
const AUTHORITY = `(?:${USERINFO}@)?(?:${IP_LITERAL}|${REG_NAME})(?::[0-9]*)?`;
const PATH_ABEMPTY = `(?:/${SEGMENT})*`;
const PATH_ABSOLUTE = `/(?:${SEGMENT_NZ}(?:/${SEGMENT})*)?`;
const PATH_NOSCHEME = `${SEGMENT_NZ_NC}(?:/${SEGMENT})*`;
const PATH_ROOTLESS = `${SEGMENT_NZ}(?:/${SEGMENT})*`;
const QUERY_AND_FRAGMENT = `(?:\\?${QUERY_OR_FRAGMENT})?(?:#${QUERY_OR_FRAGMENT})?`;

/** `URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]` */
const URI = new RegExp(
	`^${SCHEME}:(?://${AUTHORITY}${PATH_ABEMPTY}|${PATH_ABSOLUTE}|${PATH_ROOTLESS}|)${QUERY_AND_FRAGMENT}$`,
);
/** `relative-ref = relative-part [ "?" query ] [ "#" fragment ]` */
const RELATIVE_REF = new RegExp(
	`^(?://${AUTHORITY}${PATH_ABEMPTY}|${PATH_ABSOLUTE}|${PATH_NOSCHEME}|)${QUERY_AND_FRAGMENT}$`,
);
/**
 * `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`. The
 * `"v"` is an ABNF quoted literal, and RFC 5234 §2.3 makes those
 * case-insensitive — `[V1.fe]` is as valid as `[v1.fe]`.
 */
const IP_FUTURE = new RegExp(`^[vV][0-9A-Fa-f]+\\.[${UNRESERVED}${SUB_DELIMS}:]+$`);

/**
 * Whether a value is a `token-type` (RFC 6749 §A.13):
 *
 *     token-type = type-name / URI-reference
 *     type-name  = 1*name-char
 *     name-char  = "-" / "." / "_" / DIGIT / ALPHA
 *
 * Every non-empty `type-name` is a valid RFC 3986 relative reference, so this
 * reduces to "is it a URI reference?", answered by RFC 3986's grammar with
 * its structure: a lexical check would pass `https://[`, an IP-literal that
 * never closes. Brackets appear only around an IP-literal, so bracketed text
 * must be an IPv6 address or an IPvFuture.
 *
 * `""` is a URI reference but is refused: §5.1 makes `token_type` REQUIRED,
 * and an empty one is a broken adapter answer, not a type.
 */
function isTokenType(value: string): boolean {
	if (value.length === 0) return false;
	if (!URI.test(value) && !RELATIVE_REF.test(value)) return false;
	const literal = /\[([^\]]*)\]/.exec(value);
	return literal === null || isIPv6(literal[1] ?? "") || IP_FUTURE.test(literal[1] ?? "");
}

/**
 * The stored form of an upstream `token_type`: the upstream's spelling,
 * neither trimmed nor re-cased, or `undefined` when it is not a token type at
 * all ({@link isTokenType}).
 *
 * This separates a broken adapter answer from a real type this provider may
 * not hand on, the two refusals `POST /oauth/federation/:name/token` gives on
 * a refresh. It must be the grammar, not a looser bound, or garbage such as
 * `"Bearer^"` is answered as a type the upstream meant.
 */
export function canonicalTokenType(value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
	return isTokenType(value) ? value : undefined;
}

/**
 * Whether a named token type is `Bearer`, however the upstream spelled it
 * (RFC 6749 §5.1; oauth4webapi lower-cases what it was sent).
 *
 * A route asks this before handing an upstream access token on; every other
 * IANA Access Token Type is refused. `PoP` (RFC 9200) and `DPoP` (RFC 9449)
 * are sender-constrained: the recipient does not hold the key, and the
 * provider cannot present it for them. `N_A` (RFC 8693 §2.2.1) is not an
 * access token type at all. Reading any of them as `Bearer` would drop a
 * constraint or hand out a credential that only looks usable.
 *
 * An absent type is not judged here: only the caller knows whether it holds
 * an adapter's omission or an upstream's answer.
 */
export function isBearerTokenType(named: unknown): named is string {
	return typeof named === "string" && named.toLowerCase() === "bearer";
}
