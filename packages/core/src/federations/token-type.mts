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

import { isScopeToken } from "./scope.mjs";

/**
 * The one type an upstream access token may be handed on as, spelled as RFC
 * 6750 §2.1 spells the scheme. RFC 6749 §5.1 makes the comparison
 * case-insensitive ("Value is case insensitive", said there and in §4.2.2;
 * §7.1 is what defines the types themselves), so this is the spelling to
 * WRITE, never the one to test against — {@link isBearerTokenType} is that.
 */
export const BEARER_TOKEN_TYPE = "Bearer";

/**
 * The stored form of an upstream `token_type`: the name the upstream gave, or
 * `undefined` when it gave none that is a name.
 *
 * This is a bound on what could be a token type, not a parse of one. RFC 6749
 * §A.13 writes `token-type = type-name / URI-reference` with `type-name =
 * 1*name-char`, and `name-char` is only `-`, `.`, `_`, DIGIT and ALPHA — while
 * the URI-reference alternative admits far more (`urn:ietf:params:oauth:
 * token-type:jwt` is a token type and is not a `type-name`). Checking the
 * union properly would mean parsing a URI reference, for no gain: the check
 * next door is what decides, and everything this admits and §A.13 would not is
 * refused there anyway.
 *
 * So the check borrowed is `isScopeToken`, §3.3's `scope-token = 1*NQCHAR` —
 * printable ASCII without the space, the double quote or the backslash. NQCHAR
 * is a SUPERSET of both §A.13 alternatives (a URI reference cannot contain a
 * space, a quote or a backslash either), so nothing a token type may be is
 * rejected here. What it buys is the distinction the callers need: a name,
 * against `""`, a value with a space in it, and anything that is not a string
 * — an adapter answering something that could not be a token type at all.
 *
 * Nothing is trimmed or re-cased. The spelling is the upstream's, and
 * {@link isBearerTokenType} is what reads it.
 */
export function canonicalTokenType(value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
	return isScopeToken(value) ? value : undefined;
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
