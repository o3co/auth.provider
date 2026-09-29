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
 * RFC 6749 §3.3 scope grammar: `isScopeToken`, three readers of a
 * space-delimited value, and `canonicalScope`, the form a scope is stored and
 * compared in. Read any space-delimited protocol value (a scope, OIDC's
 * `prompt` and `acr_values`) through these, never by splitting on a single
 * space, which reads a tab as part of a name. Pick the reader by who wrote
 * the value:
 *
 * - a client's request parameter: `readSpaceDelimitedParameter`, strict;
 *   a malformed value is refused.
 * - the scope a token already carries (this server's tokens, a
 *   token-exchange subject): `readIssuedScope`, which never widens.
 * - anything else (an upstream's answer, an assertion's claim, client
 *   metadata, an upstream-token record): `parseScopeTokens`, tolerant.
 */

/**
 * Whether one entry is an RFC 6749 §3.3 scope-token
 * (`1*( %x21 / %x23-5B / %x5D-7E )`): one or more printable ASCII characters
 * other than the space, the double quote and the backslash.
 */
export function isScopeToken(entry: string): boolean {
	if (entry.length === 0) return false;
	return [...entry].every((character) => {
		const code = character.codePointAt(0) ?? 0;
		const printableAscii = code > 0x20 && code < 0x7f;
		return printableAscii && character !== '"' && character !== "\\";
	});
}

/**
 * The scope-tokens a value names, in order and without repeats, or none.
 *
 * Splits on any whitespace, then judges each candidate on its own, so `"\t"`
 * names nothing and `"openid\temail"` is never one scope with a tab in it. No
 * scope-token contains whitespace, so splitting on all of it cannot merge two
 * tokens or invent one. A non-string names nothing: the value came from an
 * upstream through a third-party adapter and is not trusted.
 */
export function parseScopeTokens(value: unknown): readonly string[] {
	if (typeof value !== "string") return [];
	return [...new Set(value.split(/\s+/).filter(isScopeToken))];
}

/**
 * A space-delimited request parameter, read strictly (RFC 6749 §3.3,
 * `scope-token *( SP scope-token )`): its entries in order and without
 * repeats, or `null` when malformed. For a value a client sends, where a
 * malformed one is refused (`invalid_scope`, §4.1.2.1, §5.2) and a tolerant
 * read would answer a request the client did not make.
 *
 * Only the space delimits; extra spaces are tolerated, and spaces alone yield
 * `[]` for the caller to judge. An entry that is not a scope-token (a tab,
 * newline, quote, backslash, non-printable ASCII) makes the whole value
 * malformed. Also reads OIDC's `prompt` and `acr_values` (OIDC Core §3.1.2.1).
 */
export function readSpaceDelimitedParameter(value: string): readonly string[] | null {
	const entries = value.split(" ").filter((entry) => entry !== "");
	return entries.every(isScopeToken) ? [...new Set(entries)] : null;
}

/**
 * The scope a token already carries, read so that it can never name more than
 * it did when minted: split on the space alone, keeping only scope-tokens, in
 * order and without repeats.
 *
 * For a claim this server wrote or a validator vouches for. A live token can
 * carry an entry such as `openid<TAB>email`, which named no scope when
 * minted; splitting it on the tab would grant `openid` and `email`, so it is
 * dropped. Dropping can only narrow. A non-string names nothing.
 */
export function readIssuedScope(value: unknown): readonly string[] {
	if (typeof value !== "string") return [];
	return [...new Set(value.split(" ").filter(isScopeToken))];
}

/**
 * The stored form of a scope: its tokens, space-delimited, or `undefined` when
 * it names none. What a value is written and compared as, so that neither an
 * upstream's spacing nor a repeated token can become the thing a later
 * comparison is made against.
 */
export function canonicalScope(value: unknown): string | undefined {
	const named = parseScopeTokens(value);
	return named.length > 0 ? named.join(" ") : undefined;
}
