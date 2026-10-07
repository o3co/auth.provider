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
 * RFC 6749's `token_type`: `BEARER_TOKEN_TYPE`, `canonicalTokenType` (whether
 * a value is a `token-type` at all, per §A.13 — a `type-name` or a URI
 * reference, checked against RFC 3986's grammar including its structure) and
 * `isBearerTokenType` (§5.1's case-insensitive comparison). What an upstream
 * token may be handed on as, asked by both routes that hand one on. No state.
 */
import { isIPv6 } from "node:net";
/**
 * The one type an upstream access token may be handed on as, spelled as RFC
 * 6750 §2.1 spells the scheme. RFC 6749 §5.1 makes the comparison
 * case-insensitive ("Value is case insensitive", said there and in §4.2.2;
 * §7.1 is what defines the types themselves), so this is the spelling to
 * WRITE, never the one to test against — {@link isBearerTokenType} is that.
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
const URI = new RegExp(`^${SCHEME}:(?://${AUTHORITY}${PATH_ABEMPTY}|${PATH_ABSOLUTE}|${PATH_ROOTLESS}|)${QUERY_AND_FRAGMENT}$`);
/** `relative-ref = relative-part [ "?" query ] [ "#" fragment ]` */
const RELATIVE_REF = new RegExp(`^(?://${AUTHORITY}${PATH_ABEMPTY}|${PATH_ABSOLUTE}|${PATH_NOSCHEME}|)${QUERY_AND_FRAGMENT}$`);
/**
 * `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )`. The
 * `"v"` is an ABNF quoted literal, and RFC 5234 §2.3 makes those
 * case-insensitive — `[V1.fe]` is as valid as `[v1.fe]`.
 */
const IP_FUTURE = new RegExp(`^[vV][0-9A-Fa-f]+\\.[${UNRESERVED}${SUB_DELIMS}:]+$`);
/**
 * Whether a value is a `token-type` in the sense of RFC 6749 §A.13:
 *
 *     token-type = type-name / URI-reference
 *     type-name  = 1*name-char
 *     name-char  = "-" / "." / "_" / DIGIT / ALPHA
 *
 * Every `name-char` is an RFC 3986 unreserved character, so every non-empty
 * `type-name` is itself a valid relative reference and the union reduces to
 * one question: is this a URI reference? That is answered by RFC 3986's own
 * grammar — structure included, not only the character set. A lexical check
 * let `https://[` through, an IP-literal that never closes, and read it as a
 * type the upstream meant (#649 review).
 *
 * `[` and `]` appear nowhere in RFC 3986 except around an IP-literal, so once
 * the structure matched, any bracketed text IS the IP-literal, and it has to
 * be an IPv6 address or an IPvFuture.
 *
 * The one deliberate departure: `""` is a URI reference (`path-empty` with no
 * query or fragment) and is refused here. §5.1 makes `token_type` REQUIRED,
 * and a value that names nothing does not meet that — it is an adapter
 * answering something broken, not an upstream naming a type.
 */
function isTokenType(value) {
    if (value.length === 0)
        return false;
    if (!URI.test(value) && !RELATIVE_REF.test(value))
        return false;
    const literal = /\[([^\]]*)\]/.exec(value);
    return literal === null || isIPv6(literal[1] ?? "") || IP_FUTURE.test(literal[1] ?? "");
}
/**
 * The stored form of an upstream `token_type`: the name the upstream gave, or
 * `undefined` when what it gave is not a token type at all (RFC 6749 §A.13,
 * {@link isTokenType}).
 *
 * This is what separates an adapter answering something BROKEN from an
 * upstream answering a real type this provider may not hand on — the two
 * refusals `POST /oauth/federation/:name/token` gives on a refresh. It has to
 * be the grammar and not a looser bound, or garbage such as `"Bearer^"` is
 * read as a type name and answered as if the upstream had meant it.
 *
 * Nothing is trimmed or re-cased. The spelling is the upstream's, and
 * {@link isBearerTokenType} is what reads it.
 */
export function canonicalTokenType(value) {
    if (typeof value !== "string")
        return undefined;
    return isTokenType(value) ? value : undefined;
}
/**
 * Whether a named token type is `Bearer`, however the upstream spelled it
 * (RFC 6749 §5.1; oauth4webapi lower-cases what it was sent).
 *
 * This is the question a route asks before handing an upstream's access token
 * to somebody else, and the answer is no for every other name in IANA's Access
 * Token Types registry. `PoP` (RFC 9200) and `DPoP` (RFC 9449) are
 * sender-constrained: presenting one takes a proof of possession of a key, and
 * the recipient of a token delegated by value does not hold that key — the
 * provider cannot present it on their behalf either, so there is no reading
 * under which such a token is usable once it has been handed on. `N_A` (RFC
 * 8693 §2.2.1) is not sender-constrained but is not an access token type at
 * all: it is Token Exchange's marker for "no type applies", and there is
 * nothing to present. Answering any of them as `Bearer` would be worse than
 * refusing: it drops a constraint the upstream imposed, or invents one that
 * was never issued, and hands out a credential that only looks usable.
 *
 * A type nobody named is not judged here. RFC 6749 §5.1 makes `token_type`
 * REQUIRED, so an answer that omits it comes from an adapter written before
 * the field rather than from an upstream meaning "not bearer" — but that
 * reading belongs to the caller that knows which of the two it is holding, and
 * is stated where it is made rather than hidden in this predicate.
 */
export function isBearerTokenType(named) {
    return typeof named === "string" && named.toLowerCase() === "bearer";
}
