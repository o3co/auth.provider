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
 * The trusted-proxy address vocabulary, shared by everything that asks "is
 * this hop one of ours?" so the answers cannot drift:
 *
 * - `http.trustProxy` goes straight to Express's `trust proxy`, which decides
 *   whether `X-Forwarded-For` / `-Proto` may rewrite `req.ip` / `req.protocol`;
 *   {@link checkTrustedProxyEntry} makes a typo fail at boot.
 * - `mtls.trustedProxies` (`@o3co/auth-provider-mtls`) matches
 *   `req.socket.remoteAddress` with {@link createTrustedProxyMatcher} to decide
 *   whether a forwarded client-certificate header is evidence of anything.
 *
 * Entries are Express's own forms (a named range `loopback` / `linklocal` /
 * `uniquelocal`, an IP literal, a CIDR range), so neither needs a translation
 * layer. Dotted-netmask notation (`10.0.0.0/255.0.0.0`), which `proxy-addr`
 * accepts but `BlockList.addSubnet` cannot express, is refused by name.
 *
 * An address allowlist is a network-level control, necessary but not
 * sufficient: the edge must strip inbound copies of the headers it forwards,
 * and the proxy-to-process hop must not be reachable by anyone who can spoof a
 * source address.
 */

import { BlockList, isIP } from "node:net";

// ---------------------------------------------------------------------------
// Named ranges
// ---------------------------------------------------------------------------

/**
 * One rule in a named range: a subnet base address and its prefix length.
 * Deliberately expressed as subnets even where a single address would do
 * (`::1/128`) so the whole table reads uniformly.
 */
interface Subnet {
	readonly address: string;
	readonly prefix: number;
	readonly family: "ipv4" | "ipv6";
}

/**
 * The named ranges Express's `trust proxy` understands, with the same members
 * `proxy-addr` gives them. Named rather than spelled out because the spelled-out
 * forms are wrong often enough to matter — `127.0.0.1` alone misses the rest of
 * `127.0.0.0/8` that a container reached over the loopback interface can report,
 * and misses `::1` entirely on a dual-stack listener.
 */
const NAMED_RANGES: Readonly<Record<string, readonly Subnet[]>> = {
	loopback: [
		{ address: "127.0.0.0", prefix: 8, family: "ipv4" },
		{ address: "::1", prefix: 128, family: "ipv6" },
	],
	linklocal: [
		{ address: "169.254.0.0", prefix: 16, family: "ipv4" },
		{ address: "fe80::", prefix: 10, family: "ipv6" },
	],
	uniquelocal: [
		{ address: "10.0.0.0", prefix: 8, family: "ipv4" },
		{ address: "172.16.0.0", prefix: 12, family: "ipv4" },
		{ address: "192.168.0.0", prefix: 16, family: "ipv4" },
		{ address: "fc00::", prefix: 7, family: "ipv6" },
	],
};

/** The named ranges, for operator-facing error messages and documentation. */
export const TRUSTED_PROXY_NAMED_RANGES: readonly string[] = Object.keys(NAMED_RANGES);

// ---------------------------------------------------------------------------
// Entry validation
// ---------------------------------------------------------------------------

/** Why a trusted-proxy entry is unusable, phrased for a boot-time message. */
export type TrustedProxyEntryRejection =
	| "not-a-string"
	| "empty"
	| "not-an-address-or-keyword"
	| "bad-prefix-length"
	| "netmask-notation";

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
 * A prefix length is a plain decimal integer with no sign, no leading zero and
 * no padding. `parseInt` would accept `"8abc"` and `Number` would accept
 * `" 8 "` and `"0x8"`; both would turn a malformed range into a silently
 * different one.
 */
const DECIMAL_PREFIX = /^(0|[1-9][0-9]*)$/;

/**
 * Returns `null` when `value` is a usable trusted-proxy entry, otherwise the
 * reason it is not. Split from {@link describeTrustedProxyEntryRejection} (as
 * `checkCanonicalIssuer` is) so a Zod `superRefine` can build a per-index issue
 * and a `throw` site can use the sentence.
 */
export function checkTrustedProxyEntry(value: unknown): TrustedProxyEntryRejection | null {
	if (typeof value !== "string") return "not-a-string";

	const entry = value.trim();
	if (entry === "") return "empty";

	if (Object.hasOwn(NAMED_RANGES, entry.toLowerCase())) return null;

	const slashIdx = entry.indexOf("/");
	if (slashIdx === -1) {
		return isIP(stripZone(entry)) === 0 ? "not-an-address-or-keyword" : null;
	}

	const address = entry.slice(0, slashIdx);
	const rest = entry.slice(slashIdx + 1);

	// Report a bad address before a bad prefix: `proxy.internal/24` is a
	// hostname mistake, and saying "prefix length" about it sends the operator
	// to the wrong half of the string.
	const family = isIP(stripZone(address));
	if (family === 0) return "not-an-address-or-keyword";

	// `10.0.0.0/255.0.0.0` is valid `proxy-addr` input, so an operator can
	// arrive here from Express's own documentation. Name the notation rather
	// than calling it a bad number.
	if (isIP(rest) !== 0) return "netmask-notation";

	if (!DECIMAL_PREFIX.test(rest)) return "bad-prefix-length";
	const prefix = Number(rest);
	const maxPrefix = family === 6 ? 128 : 32;
	if (prefix > maxPrefix) return "bad-prefix-length";

	return null;
}

/** Operator-facing explanation for each rejection reason. */
export function describeTrustedProxyEntryRejection(reason: TrustedProxyEntryRejection): string {
	const named = TRUSTED_PROXY_NAMED_RANGES.join(", ");
	switch (reason) {
		case "not-a-string":
			return "must be a string";
		case "empty":
			return "must not be empty";
		case "not-an-address-or-keyword":
			return (
				`is not an IP address, a CIDR range, or one of the named ranges (${named}). ` +
				"Hostnames are not accepted — the check runs against the peer address of an " +
				"already-open connection, where there is no name to resolve."
			);
		case "bad-prefix-length":
			return (
				"has a malformed CIDR prefix length. Write a plain decimal number, " +
				"0-32 for IPv4 and 0-128 for IPv6 (e.g. 10.0.0.0/8, fc00::/7)."
			);
		case "netmask-notation":
			return (
				"uses dotted-netmask notation, which is not supported. Write the " +
				"equivalent prefix length instead (10.0.0.0/255.0.0.0 is 10.0.0.0/8)."
			);
	}
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/** Options for {@link createTrustedProxyMatcher}. */
export interface TrustedProxyMatcherOptions {
	/**
	 * Config key named in a boot-time error, so the operator is pointed at the
	 * setting they wrote rather than at this function. Defaults to
	 * `"trusted-proxies"`.
	 */
	readonly label?: string;
}

/**
 * Builds a predicate answering whether an observed peer address is a
 * configured trusted proxy.
 *
 * Feed it the peer address (`req.socket.remoteAddress`), never `req.ip`: with
 * `trust proxy` on, `req.ip` comes from `X-Forwarded-For`, and authenticating a
 * hop with it makes the allowlist decorative. An IPv4 entry also matches the
 * IPv4-mapped IPv6 form (`::ffff:10.0.0.7`) of a dual-stack listener. An empty
 * list trusts nothing (fail closed); callers that need a non-empty list enforce
 * it at boot.
 *
 * @throws Error at construction on an unusable entry (see
 * {@link checkTrustedProxyEntry}), which would otherwise never match.
 */
export const createTrustedProxyMatcher = (
	entries: readonly string[],
	options: TrustedProxyMatcherOptions = {},
): ((remoteAddress: string | undefined) => boolean) => {
	const label = options.label ?? "trusted-proxies";
	const blockList = new BlockList();
	let ruleCount = 0;

	entries.forEach((rawEntry, index) => {
		const rejection = checkTrustedProxyEntry(rawEntry);
		if (rejection !== null) {
			throw new Error(
				`createTrustedProxyMatcher: ${label}[${index}] = ${JSON.stringify(rawEntry)} ` +
					describeTrustedProxyEntryRejection(rejection),
			);
		}

		const entry = (rawEntry as string).trim();
		const named = NAMED_RANGES[entry.toLowerCase()];
		if (named !== undefined) {
			for (const subnet of named) {
				blockList.addSubnet(subnet.address, subnet.prefix, subnet.family);
				ruleCount += 1;
			}
			return;
		}

		const slashIdx = entry.indexOf("/");
		if (slashIdx === -1) {
			const address = stripZone(entry);
			blockList.addAddress(address, isIP(address) === 6 ? "ipv6" : "ipv4");
			ruleCount += 1;
			return;
		}

		// `BlockList.addSubnet` masks the host bits itself, so `10.4.5.6/16`
		// registers 10.4.0.0/16 rather than being rejected — the forgiving
		// reading of what an operator who wrote the proxy's own address plus a
		// prefix meant.
		const address = stripZone(entry.slice(0, slashIdx));
		blockList.addSubnet(
			address,
			Number(entry.slice(slashIdx + 1)),
			isIP(address) === 6 ? "ipv6" : "ipv4",
		);
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
