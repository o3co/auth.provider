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
 * Reading a `WWW-Authenticate` answer from the Store (RFC 9110 §11.6.1).
 *
 * `HttpUserRepository` asks one question of it: does the answer carry a
 * `Bearer` challenge (RFC 6750 §3) — the Store saying it refused the
 * credential this deployment presented, not the user. Only the scheme is
 * read; nothing the Store wrote after it is kept, so nothing it wrote can
 * reach an error this adapter throws.
 */
/**
 * A quoted-string (RFC 9110 §5.6.4), escapes included — and one left
 * unterminated runs to the end of the value, so what follows its opening
 * quote is its content, never a challenge. Each character is consumed once
 * (a backslash with the character after it, when there is one), so a value
 * of escaped quotes with no closing one costs a scan: matching up to a
 * closing quote that never comes retried from every quote, which a 64 KiB
 * value turned into seconds per answer.
 */
const QUOTED_STRING = /"(?:[^"\\]|\\[\s\S]?)*(?:"|$)/g;
/**
 * An auth-scheme `Bearer`, case-insensitive (RFC 9110 §11.1), where a
 * challenge begins — the value's start or after a comma — and followed by the
 * value's end, a comma, or whitespace that does not lead to `=` (which would
 * make `bearer` a parameter's name, not a scheme: `bearer  = 1` is one).
 *
 * The whitespace after the scheme is taken whole, once: the lookahead
 * captures the entire run and the backreference consumes exactly it, and a
 * lookahead is never re-entered, so a long run followed by `=` is not
 * retried from every shorter run. `(?<=[ \t])` then requires that the run
 * was not empty, so `bearerish` is not the scheme.
 */
const BEARER_CHALLENGE = /(?:^|,)[ \t]*bearer(?=([ \t]*))\1(?:$|,|(?<=[ \t])(?!=))/i;
/**
 * Whether a `WWW-Authenticate` value carries a `Bearer` challenge (RFC 6750
 * §3). Quoted strings are blanked first, so `realm="… Bearer …"` is not one;
 * several header lines arrive joined by `, `, which this reads as the
 * challenge list it is. A malformed line — a quoted string never closed —
 * hides whatever follows it, including a challenge on a later line: the
 * answer is then read as it would be without one, never the other way.
 */
export function hasBearerChallenge(value) {
    return value !== null && BEARER_CHALLENGE.test(value.replace(QUOTED_STRING, '""'));
}
