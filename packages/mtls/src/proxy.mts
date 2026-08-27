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
 * Trusted-proxy allowlist matching for the forwarded-certificate header source
 * (issue #280).
 *
 * RFC 8705 §3 requires the client certificate to reach the authorization
 * server either from the TLS layer or from an **authenticated** trusted proxy.
 * `source = "header"` is the second shape, and the only thing on an HTTP
 * request that an attacker cannot choose is the address of the peer that
 * opened the TCP connection. So that — `req.socket.remoteAddress` — is what
 * this matcher is fed.
 *
 * **Never `req.ip`.** `req.ip` is derived from `X-Forwarded-For` whenever
 * Express `trust proxy` is on, which makes it exactly as forgeable as the
 * certificate header we are trying to authenticate. Using it here would make
 * the allowlist decorative.
 *
 * ### Relationship to `http.trustProxy`
 *
 * `http.trustProxy` (core config) drives Express's `trust proxy` setting: it
 * decides whether `X-Forwarded-For` may rewrite `req.ip` for rate limiting and
 * URL reconstruction. It is a **boolean** today and says nothing about *which*
 * hop is trusted. This allowlist is a separate, narrower control with a
 * different subject (the TCP peer, not a header chain), and it is deliberately
 * not derived from `http.trustProxy` — turning on `X-Forwarded-For` parsing for
 * rate limiting must not silently start accepting forwarded client
 * certificates.
 *
 * Issue #292 widens `http.trustProxy` into a CIDR / hop policy. The entry
 * vocabulary here (IP literals plus the `loopback` keyword) is the same
 * vocabulary Express's `trust proxy` already accepts, so that work can extend
 * this list with ranges without a breaking change to the config shape. CIDR
 * entries are rejected at boot until then, rather than silently never matching.
 */

import { BlockList, isIP } from "node:net";

/**
 * The `loopback` keyword — matches `127.0.0.0/8` and `::1`, the standard
 * sidecar deployment shape (Envoy / nginx in the same pod or on the same host,
 * reaching the auth provider over the loopback interface).
 *
 * Named rather than spelled out because `127.0.0.1` alone is wrong often
 * enough to matter: a container reached over the loopback interface can report
 * any address in `127.0.0.0/8`, and a dual-stack listener reports `::1`.
 */
const LOOPBACK_KEYWORD = "loopback";

/**
 * Strip an IPv6 zone index (`fe80::1%en0`). `net.isIP` accepts the zone form
 * but `BlockList.check` does not, so an observed link-local address would
 * throw instead of comparing. The zone is a local interface selector, not part
 * of the address identity, so dropping it is the correct comparison.
 */
const stripZone = (address: string): string => {
	const zoneIdx = address.indexOf("%");
	return zoneIdx === -1 ? address : address.slice(0, zoneIdx);
};

/**
 * Build a predicate that answers whether an observed peer address is one of
 * the configured trusted proxies.
 *
 * Entry forms:
 *   - `"loopback"` — `127.0.0.0/8` and `::1`.
 *   - An IPv4 or IPv6 literal — matched exactly, in any textual form. An IPv4
 *     entry also matches the IPv4-mapped IPv6 form (`::ffff:10.0.0.7`) that
 *     Node reports on a dual-stack listener, so operators do not have to know
 *     which family the listener bound.
 *
 * An empty list produces a predicate that trusts nothing. That is the correct
 * fail-closed behaviour: callers enforce "header source requires a non-empty
 * allowlist" at boot with an operator-facing message, and this layer must not
 * be the thing that decides an unconfigured deployment is safe.
 *
 * Throws at construction on an entry that is neither the keyword nor an IP
 * literal. A hostname or a typo would otherwise never match and turn a
 * deliberate allowlist into a silent outage of the mTLS binding.
 */
export const createTrustedProxyMatcher = (
	entries: readonly string[],
): ((remoteAddress: string | undefined) => boolean) => {
	const blockList = new BlockList();
	let ruleCount = 0;

	entries.forEach((rawEntry, index) => {
		const entry = rawEntry.trim();

		if (entry.toLowerCase() === LOOPBACK_KEYWORD) {
			blockList.addSubnet("127.0.0.0", 8, "ipv4");
			blockList.addAddress("::1", "ipv6");
			ruleCount += 2;
			return;
		}

		if (entry.includes("/")) {
			throw new Error(
				`createTrustedProxyMatcher: trusted-proxies[${index}] = "${rawEntry}" looks like a CIDR range. ` +
					"CIDR ranges are not supported yet — see o3co/auth.provider#292, which introduces the " +
					"shared trusted-proxy range vocabulary. List the individual proxy addresses, or use " +
					'the "loopback" keyword, until then.',
			);
		}

		const family = isIP(entry);
		if (family === 0) {
			throw new Error(
				`createTrustedProxyMatcher: trusted-proxies[${index}] = "${rawEntry}" is not a valid IP address ` +
					'or the "loopback" keyword. Hostnames are not accepted — the check runs against the ' +
					"peer address of an already-open connection, where there is no name to resolve.",
			);
		}

		blockList.addAddress(stripZone(entry), family === 6 ? "ipv6" : "ipv4");
		ruleCount += 1;
	});

	// No rules at all: short-circuit rather than calling into BlockList, whose
	// `check` would answer `false` anyway. Explicit so the fail-closed intent
	// reads at the call site of this factory rather than in BlockList's docs.
	if (ruleCount === 0) return () => false;

	return (remoteAddress: string | undefined): boolean => {
		if (remoteAddress === undefined || remoteAddress.length === 0) return false;
		const address = stripZone(remoteAddress);
		const family = isIP(address);
		if (family === 0) return false;
		return blockList.check(address, family === 6 ? "ipv6" : "ipv4");
	};
};
