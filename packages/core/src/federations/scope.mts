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
 * RFC 6749 §3.3's scope grammar: `isScopeToken`, `parseScopeTokens` and
 * `canonicalScope`, the one form a scope is written and compared in. Read a
 * scope through these rather than splitting it by hand: a split on a single
 * space reads a tab as part of a scope's name. No state.
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
export function parseScopeTokens(value: unknown): readonly string[] {
	if (typeof value !== "string") return [];
	return [...new Set(value.split(/\s+/).filter(isScopeToken))];
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
