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
 * The loopback-hostname vocabulary: the one definition for everything that
 * allows `http://` toward hosts whose traffic never leaves the machine
 * (`checkSecureEndpoint` for store endpoints; `checkRedirectShape` for
 * federation redirects, local development and RFC 8252 §7.3 native-client
 * listeners). `createAppleProvider` reads it the other way round and refuses a
 * loopback return URL at boot, because Apple refuses one even over `https`:
 * the predicate answers "is this loopback", not "is this allowed".
 *
 * Copies of this predicate drift; `core/src/__tests__/designVocabulary.drift.test.mts`
 * fails a second definition (map row in `docs/design-vocabulary.md`).
 *
 * It answers whether a hostname NAMES the loopback interface. It is
 * deliberately separate from `trusted-proxy.mts`'s `loopback` range, which
 * matches socket ADDRESSES via `BlockList` and never sees `localhost` or
 * brackets.
 */

/** Dotted-quad IPv4, the only numeric form the WHATWG URL parser emits. */
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Whether `hostname` names an address that never leaves the machine:
 * - `localhost`, exact (`URL.hostname` is already lowercased; a raw
 *   `LOCALHOST` is a typo, not an intent);
 * - IPv6 loopback both as `URL.hostname` reports it (`[::1]`) and raw (`::1`);
 * - the whole `127.0.0.0/8` block as a dotted quad (`127.0.0.53` too).
 *
 * IPv4 shorthand (`127.1`) and full-form IPv6 are NOT accepted: `URL.hostname`
 * normalizes both, so such a value did not come from a URL, and accepting
 * textual variants open-endedly turns a comparison into a parser.
 */
export function isLoopbackHostname(hostname: string): boolean {
	if (hostname === "localhost") return true;
	if (hostname === "[::1]" || hostname === "::1") return true;

	const v4 = IPV4.exec(hostname);
	if (v4 === null) return false;
	const octets = [v4[1], v4[2], v4[3], v4[4]].map(Number);
	return octets[0] === 127 && octets.every((o) => o <= 255);
}
