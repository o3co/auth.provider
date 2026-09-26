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
 * The loopback-hostname vocabulary — one definition, shared by everything in
 * this repository that carves `http://` out for hosts whose traffic never
 * leaves the machine (#364).
 *
 * Consumers today:
 *
 *   - **`checkSecureEndpoint`** (`@o3co/auth-provider-foundation`, #285):
 *     Store endpoints carry plaintext credentials, so `http://` is refused —
 *     except toward a loopback host, where there is no path to eavesdrop on.
 *   - **`checkRedirectShape`** (`@o3co/auth-provider-session`, #278): federation
 *     redirect targets must be `https://` — except a loopback host, which is
 *     where a native client's RFC 8252 §7.3 listener and local development
 *     live, and neither can obtain a certificate.
 *
 * Both print the same operator-facing promise — "localhost, 127.0.0.0/8,
 * [::1]" — and before this module each backed it with its own copy of the
 * predicate. The copies drifted within one commit of being written (one
 * accepted unbracketed `::1`, the other did not) under doc comments that were
 * still identical, which is the failure mode #292 moved the trusted-proxy
 * vocabulary here to prevent. The map row lives in
 * `docs/design-vocabulary.md`; the drift guard in
 * `core/src/__tests__/designVocabulary.drift.test.mts` fails any second
 * definition.
 *
 * This predicate answers "does this hostname NAME the loopback interface" —
 * a vocabulary question about a string. It is deliberately not merged with
 * `trusted-proxy.mts`'s `loopback` named range, which answers "does this
 * socket ADDRESS fall inside 127.0.0.0/8 or ::1/128" via `BlockList` — an
 * address-matching question that never sees `localhost` and never sees
 * brackets. Same concept, two representations; each home states the other.
 */
/** Dotted-quad IPv4, the only numeric form the WHATWG URL parser emits. */
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
/**
 * Whether `hostname` names an address that never leaves the machine.
 *
 * Accepted forms:
 *
 *   - `localhost` (exact — `URL.hostname` has already lowercased a URL host,
 *     and a raw config value spelled `LOCALHOST` is a typo, not an intent);
 *   - IPv6 loopback both as `URL.hostname` reports it (`[::1]`, always
 *     bracketed) and as a raw hostname outside a URL (`::1`) — both denote
 *     the same address, and accepting only one form is exactly how the
 *     pre-#364 copies drifted;
 *   - the whole `127.0.0.0/8` block as a dotted quad — `127.0.0.53`
 *     (systemd-resolved) and friends are as local as `127.0.0.1`.
 *
 * IPv4 shorthand (`127.1`) and full-form IPv6 (`0:0:0:0:0:0:0:1`) are
 * deliberately NOT accepted: `URL.hostname` normalizes both before they get
 * here, so a value still in that shape did not come from a URL — and
 * accepting textual variants open-endedly is how a comparison becomes a
 * parser.
 */
export function isLoopbackHostname(hostname) {
    if (hostname === "localhost")
        return true;
    if (hostname === "[::1]" || hostname === "::1")
        return true;
    const v4 = IPV4.exec(hostname);
    if (v4 === null)
        return false;
    // The whole 127.0.0.0/8 block is loopback, not just 127.0.0.1.
    const octets = [v4[1], v4[2], v4[3], v4[4]].map(Number);
    return octets[0] === 127 && octets.every((o) => o <= 255);
}
