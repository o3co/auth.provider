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
 * RFC 6749 §3.3's scope grammar: `isScopeToken`, the three readers of a
 * space-delimited value, and `canonicalScope`, the one form a scope is
 * written and compared in. Read a scope — or any other space-delimited
 * protocol value, such as OIDC's `prompt` and `acr_values` — through these
 * rather than splitting it by hand: a split on a single space reads a tab as
 * part of a name. Which reader a site uses depends on who wrote the value:
 *
 * - a client's request parameter: `readSpaceDelimitedParameter`, strict. A
 *   malformed value is the request's fault and is refused (`invalid_scope`
 *   for a scope, RFC 6749 §4.1.2.1 / §5.2).
 * - the scope a token already carries — this server's own access and refresh
 *   tokens, a token-exchange subject: `readIssuedScope`, which never widens.
 *   A token minted before requests were read strictly can hold an entry such
 *   as `openid<TAB>email` that named no scope; it stays naming none.
 * - anything else — an upstream's answer, an assertion's claim, a client
 *   metadata document, an upstream-token record: `parseScopeTokens`,
 *   tolerant. The value is read for what it names, and one that names
 *   nothing is never read as absent.
 *
 * No state.
 */
/**
 * Whether one entry is a scope-token.
 *
 * RFC 6749 §3.3 writes the grammar in hex — `scope-token = 1*( %x21 / %x23-5B
 * / %x5D-7E )` — which reads, in words: one or more printable ASCII
 * characters, excluding the space, the double quote and the backslash. The
 * space is excluded because it is the delimiter between tokens.
 *
 * Spelled out as the predicate rather than as a character-class regex, because
 * `[\x21\x23-\x5B\x5D-\x7E]` is the kind of thing a reader has to decode
 * before they can tell whether it is right.
 */
export function isScopeToken(entry) {
    if (entry.length === 0)
        return false;
    return [...entry].every((character) => {
        const code = character.codePointAt(0) ?? 0;
        const printableAscii = code > 0x20 && code < 0x7f;
        return printableAscii && character !== '"' && character !== "\\";
    });
}
/**
 * The scope-tokens a value names, in order and without repeats, or none.
 *
 * Two steps, deliberately separate: split the text into candidates, then judge
 * each candidate on its own. Splitting on a single space and dropping empties
 * conflates the two and gets both wrong — `"\t"` reads as a scope named tab,
 * and `"openid\temail"` as one scope with a tab inside its name, neither of
 * which the grammar admits.
 *
 * Whitespace other than the space is not a delimiter in the grammar, but no
 * scope-token may contain it either, so splitting on all of it cannot merge
 * two tokens or invent one.
 *
 * Anything that is not a string names nothing: a value reaching here has come
 * from an upstream IdP through a third-party adapter, and is not believed
 * before it is read (D5).
 */
export function parseScopeTokens(value) {
    if (typeof value !== "string")
        return [];
    return [...new Set(value.split(/\s+/).filter(isScopeToken))];
}
/**
 * A space-delimited request parameter, read strictly: its entries in order and
 * without repeats, or `null` when it is malformed.
 *
 * The counterpart of {@link parseScopeTokens} for a value a client sends in a
 * request, where RFC 6749 names the answer to a malformed one (`invalid_scope`,
 * §4.1.2.1 and §5.2) and reading it tolerantly would answer a request the
 * client did not make. The grammar is §3.3's — `scope-token *( SP
 * scope-token )`:
 *
 * - the space is the only delimiter. Runs of spaces, and spaces at either
 *   end, are tolerated: they can neither merge two entries nor invent one.
 *   A value of spaces alone names nothing (`[]`), and the caller decides
 *   whether that is an omitted parameter or a refusal.
 * - every entry must be a scope-token ({@link isScopeToken}). A tab, a
 *   newline, a quote, a backslash or anything outside printable ASCII makes
 *   the whole value malformed, rather than being dropped or read as a
 *   delimiter.
 *
 * OpenID Connect's other space-delimited request parameters (`prompt`,
 * `acr_values`, OIDC Core §3.1.2.1) are read with it too: their values are
 * printable ASCII without spaces, which the same entry grammar admits.
 */
export function readSpaceDelimitedParameter(value) {
    const entries = value.split(" ").filter((entry) => entry !== "");
    return entries.every(isScopeToken) ? [...new Set(entries)] : null;
}
/**
 * The scope a token already carries, read so that it can never name more than
 * it did when the token was minted: split on the space alone, keeping only the
 * scope-tokens, in order and without repeats.
 *
 * The reader for a claim this server wrote — or a validator vouches for — as
 * opposed to an upstream's answer ({@link parseScopeTokens}). The difference
 * is what a tab does. Before requests were read strictly, a grant could mint a
 * scope as the client sent it, so a live token can carry `openid<TAB>email` as
 * one entry. That entry named no scope, released no claim and matched no
 * ceiling. Splitting it on the tab would turn it into `openid` and `email` —
 * a scope the token was never granted — so an entry that is not a scope-token
 * is dropped instead. Dropping can only narrow.
 *
 * Runs of spaces and spaces at either end name the same scopes: they can
 * neither merge two entries nor invent one. Anything that is not a string
 * names nothing.
 */
export function readIssuedScope(value) {
    if (typeof value !== "string")
        return [];
    return [...new Set(value.split(" ").filter(isScopeToken))];
}
/**
 * The stored form of a scope: its tokens, space-delimited, or `undefined` when
 * it names none. What a value is written and compared as, so that neither an
 * upstream's spacing nor a repeated token can become the thing a later
 * comparison is made against.
 */
export function canonicalScope(value) {
    const named = parseScopeTokens(value);
    return named.length > 0 ? named.join(" ") : undefined;
}
