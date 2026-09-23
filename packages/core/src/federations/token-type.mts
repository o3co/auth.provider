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
 * The one type an upstream access token may be handed on as, spelled as RFC
 * 6750 §2.1 spells the scheme. RFC 6749 §5.1 makes the comparison
 * case-insensitive ("Value is case insensitive", said there and in §4.2.2;
 * §7.1 is what defines the types themselves), so this is the spelling to
 * WRITE, never the one to test against — {@link isBearerTokenType} is that.
 */
export const BEARER_TOKEN_TYPE = "Bearer";

/**
 * RFC 3986 §2: the characters a URI may contain outside a percent-encoding —
 * unreserved (`ALPHA DIGIT - . _ ~`), gen-delims (`: / ? # [ ] @`) and
 * sub-delims (`! $ & ' ( ) * + , ; =`). `%` is not here: it is only valid as
 * the start of a pct-encoded octet, which is checked on its own.
 */
const URI_CHARACTER = /[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=]/;
const PCT_ENCODED = /^%[0-9A-Fa-f]{2}/;

/**
 * Whether a value is a `token-type` in the sense of RFC 6749 §A.13:
 *
 *     token-type = type-name / URI-reference
 *     type-name  = 1*name-char
 *     name-char  = "-" / "." / "_" / DIGIT / ALPHA
 *
 * Every `name-char` is an RFC 3986 unreserved character, so every
 * `type-name` is itself a valid (relative) URI reference and the union
 * reduces to one question: is this a URI reference? That is answered
 * lexically — every character is one RFC 3986 admits, and every `%` begins a
 * pct-encoded octet. The structural rules a full parse would add (`[` only in
 * an IP-literal host, no `:` in a relative reference's first segment) are not
 * checked; a value that breaks only those is a URI-shaped string nobody
 * issues as a token type, and reading it as a name changes only WHICH
 * refusal it gets, never whether it is refused.
 *
 * `"Bearer^"`, `"a{b}"`, `"DPoP "` and `""` are not token types: each has a
 * character no URI may contain, or none at all.
 */
function isTokenType(value: string): boolean {
	if (value.length === 0) return false;
	let i = 0;
	while (i < value.length) {
		if (value[i] === "%") {
			if (!PCT_ENCODED.test(value.slice(i))) return false;
			i += 3;
			continue;
		}
		if (!URI_CHARACTER.test(value[i] ?? "")) return false;
		i += 1;
	}
	return true;
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
export function canonicalTokenType(value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
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
export function isBearerTokenType(named: unknown): named is string {
	return typeof named === "string" && named.toLowerCase() === "bearer";
}
