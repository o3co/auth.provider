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

/** A quoted-string (RFC 9110 §5.6.4), escapes included. */
const QUOTED_STRING = /"(?:[^"\\]|\\.)*"/g;

/**
 * An auth-scheme `Bearer`, case-insensitive (RFC 9110 §11.1), where a
 * challenge begins — the value's start or after a comma — and followed by the
 * value's end, a comma, or whitespace that does not lead to `=` (which would
 * make `bearer` a parameter's name, not a scheme).
 */
const BEARER_CHALLENGE = /(?:^|,)[ \t]*bearer(?:[ \t]*(?:,|$)|[ \t]+(?!=))/i;

/**
 * Whether a `WWW-Authenticate` value carries a `Bearer` challenge (RFC 6750
 * §3). Quoted strings are blanked first, so `realm="… Bearer …"` is not one;
 * several header lines arrive joined by `, `, which this reads as the
 * challenge list it is.
 */
export function hasBearerChallenge(value: string | null): boolean {
	return value !== null && BEARER_CHALLENGE.test(value.replace(QUOTED_STRING, '""'));
}
