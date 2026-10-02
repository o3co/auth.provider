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
 * The outbound fetch's destination rules, as pure decisions with no I/O: the
 * host-list grammar (an exact host or a `.suffix`, both sides canonicalised as
 * the URL parser canonicalises a host), what a URL must be before its host is
 * resolved, and what the resolved addresses must be before a connection is
 * made. Its refusal vocabulary is core's own: callers see `isOutboundRefusal`
 * (`outbound-fetch.mts`), never the codes.
 */

import { isIP } from "node:net";
import { z } from "zod";
import { isLoopbackHostname } from "./loopback.mjs";
import { isSpecialUseAddress } from "./special-use.mjs";

/** Where a URL came from: decides whether `internalHosts` may apply. */
export type OutboundUrlSource = "registration" | "request";

/** The policy refusing a destination or an answer. */
type OutboundRefusalReason =
	| "url_unparseable"
	| "scheme_not_allowed"
	| "userinfo_present"
	| "port_not_allowed"
	| "host_not_allowed"
	| "special_use_address"
	| "redirect_refused"
	| "response_too_large"
	| "unsupported_encoding";

/** The exchange failing for a reason that is not the policy's. */
type OutboundFailureReason = "resolution_failed" | "timeout" | "network_error";

export type OutboundFetchErrorReason = OutboundRefusalReason | OutboundFailureReason;

const REFUSALS: ReadonlySet<OutboundFetchErrorReason> = new Set<OutboundRefusalReason>([
	"url_unparseable",
	"scheme_not_allowed",
	"userinfo_present",
	"port_not_allowed",
	"host_not_allowed",
	"special_use_address",
	"redirect_refused",
	"response_too_large",
	"unsupported_encoding",
]);

/**
 * A refusal or failure of the outbound fetch. `reason` is a code
 * (`loggableError` keeps it); the message is core's own words and the host,
 * never anything the peer sent.
 */
export class OutboundFetchError extends Error {
	override readonly name = "OutboundFetchError";
	readonly reason: OutboundFetchErrorReason;

	constructor(reason: OutboundFetchErrorReason, host?: string, detail?: string) {
		const verdict = REFUSALS.has(reason) ? "refused" : "failed";
		super(
			`outbound fetch${host !== undefined ? ` to ${host}` : ""} ${verdict}: ${reason}` +
				(detail !== undefined ? ` (${detail})` : ""),
		);
		this.reason = reason;
	}

	/** Whether this is the policy refusing, as against the exchange failing. */
	get refusal(): boolean {
		return REFUSALS.has(this.reason);
	}
}

/** One host-list entry: a canonical host, and whether it also covers every subdomain. */
export interface HostPattern {
	readonly host: string;
	readonly suffix: boolean;
}

/** A DNS label of letters, digits and inner hyphens (RFC 1123), after IDNA. */
const LDH_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** `hostname` as the URL parser gave it, less one trailing dot; `undefined` for an empty label. */
const withoutRootDot = (hostname: string): string | undefined => {
	const host = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
	if (host === "" || host.endsWith(".") || host.startsWith(".") || host.includes("..")) {
		return undefined;
	}
	return host;
};

/**
 * The canonical form of `url`'s host, as host lists are matched: the URL
 * parser's (lower case, punycode, canonical IPv4 and bracketed IPv6) with one
 * trailing dot removed. `undefined` when a label is empty.
 */
export function urlHost(url: URL): string | undefined {
	return withoutRootDot(url.hostname);
}

/**
 * `entry` read as a host-list entry: a host name of letters, digits and
 * hyphens once IDNA has run, an IPv4 address or an IPv6 address (bracketed
 * or not), optionally after a `.` that also covers every subdomain of a
 * name. `undefined` for anything else (a wildcard, a scheme, a port, a path,
 * credentials, an empty label, a suffix on an address).
 */
export function readHostEntry(entry: string): HostPattern | undefined {
	const trimmed = entry.trim();
	const suffix = trimmed.startsWith(".");
	const body = suffix ? trimmed.slice(1) : trimmed;
	if (body === "" || /[\s/\\?#@]/.test(body)) return undefined;
	const bracketed = body.startsWith("[");
	if (bracketed && !/^\[[^\]]+\]$/.test(body)) return undefined;
	if (!bracketed && body.includes(":") && isIP(body) !== 6) return undefined;
	let url: URL;
	try {
		url = new URL(`https://${!bracketed && isIP(body) === 6 ? `[${body}]` : body}/`);
	} catch {
		return undefined;
	}
	if (url.port !== "" || url.pathname !== "/" || url.username !== "" || url.password !== "") {
		return undefined;
	}
	const host = withoutRootDot(url.hostname);
	if (host === undefined) return undefined;
	const address = host.startsWith("[") || isIP(host) === 4;
	if (suffix && address) return undefined;
	if (!address && !host.split(".").every((label) => LDH_LABEL.test(label))) return undefined;
	return { host: hostIdentity(host), suffix };
}

/** The eight groups of a canonical bracketed IPv6 host, or `undefined`. */
const ipv6Groups = (host: string): number[] | undefined => {
	if (!host.startsWith("[") || !host.endsWith("]")) return undefined;
	const halves = host.slice(1, -1).split("::");
	const part = (text: string | undefined) =>
		text === undefined || text === "" ? [] : text.split(":").map((g) => Number.parseInt(g, 16));
	const head = part(halves[0]);
	const tail = part(halves[1]);
	const groups =
		halves.length === 2
			? [...head, ...Array.from({ length: 8 - head.length - tail.length }, () => 0), ...tail]
			: head;
	return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff) ? groups : undefined;
};

/**
 * The identity a host is matched by: its canonical form, with an IPv6
 * literal that embeds an IPv4 address (IPv4-mapped `::ffff:a.b.c.d`,
 * IPv4-translated `::ffff:0:a.b.c.d`, IPv4-compatible `::a.b.c.d` but for
 * `::` and `::1`) read as that IPv4 address. Entries and URL hosts both go
 * through it, so any spelling of one address matches any other.
 */
const hostIdentity = (host: string): string => {
	const g = ipv6Groups(host);
	if (g === undefined) return host;
	const zero = (from: number, to: number) => g.slice(from, to).every((group) => group === 0);
	const embeds =
		(zero(0, 5) && g[5] === 0xffff) ||
		(zero(0, 4) && g[4] === 0xffff && g[5] === 0) ||
		(zero(0, 6) && !(g[6] === 0 && (g[7] ?? 0) <= 1));
	if (!embeds) return host;
	const high = g[6] ?? 0;
	const low = g[7] ?? 0;
	return [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
};

/**
 * Whether `patterns` cover `host`: a URL's `hostname` as the URL parser gives
 * it, a trailing dot or not.
 */
export function matchesHostList(patterns: readonly HostPattern[], host: string): boolean {
	const key = hostIdentity(withoutRootDot(host) ?? host);
	return patterns.some(
		(pattern) => key === pattern.host || (pattern.suffix && key.endsWith(`.${pattern.host}`)),
	);
}

/**
 * A host list of `core.outbound`: a list, or the comma-separated string an
 * environment variable carries (each entry trimmed, empty ones dropped). Each
 * entry is a host or a `.suffix` (`readHostEntry`); any other refuses boot,
 * naming its index.
 */
const outboundHostList = z
	.union([z.array(z.string()), z.string()])
	.transform((value) =>
		Array.isArray(value)
			? value
			: value
					.split(",")
					.map((entry) => entry.trim())
					.filter((entry) => entry.length > 0),
	)
	.pipe(
		z.array(
			z.string().refine((entry) => readHostEntry(entry) !== undefined, {
				error:
					"must be a host name or an IP address, with a leading `.` to cover a domain and " +
					"every subdomain of it",
			}),
		),
	);

/** The longest deadline a timer holds: Node runs a longer one at once. */
export const MAX_TIMEOUT_MS = 2_147_483_647;

/**
 * A positive whole number: a number, or a string of decimal digits as an
 * environment variable carries it. Nothing else is converted (`true`, `[1]`,
 * `""` and `"1e3"` are refused).
 */
const wholeNumber = z
	.union([z.number(), z.string().regex(/^\s*\d+\s*$/, { error: "must be a whole number" })])
	.transform(Number)
	.pipe(z.number().int().positive());

/**
 * `core.outbound`, this policy's section: core's schema declares it under
 * `core`, and `outboundPolicyOf` (`outbound-fetch.mts`) alone reads it.
 * Strict, and each key optional: an absent key takes its default there, and
 * a present section that does not parse refuses boot. Each leaf reads the
 * string an environment variable carries.
 */
export const OutboundSectionSchema = z
	.object({
		// Exact hosts or `.suffix` entries; empty admits any host the rules admit.
		allowedHosts: outboundHostList.optional(),
		// Same forms; wins over the other lists.
		deniedHosts: outboundHostList.optional(),
		// Hosts admitted at special-use addresses, for a URL from a client
		// registration only; plain http only for a loopback one.
		internalHosts: outboundHostList.optional(),
		// One deadline over resolution, connection, TLS, headers and body. It
		// shortens a caller's own deadline, never lengthens it.
		timeoutMs: wholeNumber.pipe(z.number().max(MAX_TIMEOUT_MS)).optional(),
		// The most bytes of a 2xx body that are read.
		maxResponseBytes: wholeNumber.optional(),
		// `"direct"` states that the outbound fetch connects directly while
		// HTTPS_PROXY / HTTP_PROXY is set; without it, building one refuses.
		egress: z.enum(["direct"]).optional(),
	})
	.strict();

/** The policy `core.outbound` states, its lists read into patterns. */
export interface OutboundPolicy {
	readonly allowedHosts: readonly HostPattern[];
	readonly deniedHosts: readonly HostPattern[];
	readonly internalHosts: readonly HostPattern[];
	readonly timeoutMs: number;
	readonly maxResponseBytes: number;
	readonly egress: "direct" | undefined;
}

/**
 * The ports the Fetch standard calls bad (fetch.spec.whatwg.org, "bad port"),
 * which `fetch` refuses and a raw `https.request` would not.
 */
const BAD_PORTS: ReadonlySet<string> = new Set([
	"0",
	"1",
	"7",
	"9",
	"11",
	"13",
	"15",
	"17",
	"19",
	"20",
	"21",
	"22",
	"23",
	"25",
	"37",
	"42",
	"43",
	"53",
	"69",
	"77",
	"79",
	"87",
	"95",
	"101",
	"102",
	"103",
	"104",
	"109",
	"110",
	"111",
	"113",
	"115",
	"117",
	"119",
	"123",
	"135",
	"137",
	"139",
	"143",
	"161",
	"179",
	"389",
	"427",
	"465",
	"512",
	"513",
	"514",
	"515",
	"526",
	"530",
	"531",
	"532",
	"540",
	"548",
	"554",
	"556",
	"563",
	"587",
	"601",
	"636",
	"989",
	"990",
	"993",
	"995",
	"1719",
	"1720",
	"1723",
	"2049",
	"3659",
	"4045",
	"4190",
	"5060",
	"5061",
	"6000",
	"6566",
	"6665",
	"6666",
	"6667",
	"6668",
	"6669",
	"6679",
	"6697",
	"10080",
]);

/** A URL the policy admits, ready to be resolved and connected to. */
export interface AdmittedDestination {
	readonly url: URL;
	/** The canonical host, for the lists and the log. */
	readonly host: string;
	/** The address itself, when the host is an IP literal: nothing is resolved. */
	readonly literal: string | undefined;
	/** Whether the host may be at a special-use address. */
	readonly internal: boolean;
	/** Plain http: admitted only toward the loopback interface. */
	readonly plaintext: boolean;
}

/**
 * The URL `input` names, if the policy admits it before any name is
 * resolved: https (or http to a loopback host `internalHosts` lists, for a
 * registration's URL), no credentials, no bad port, the host lists, and an
 * IP-literal host outside the special-use ranges unless it is internal.
 * Throws an {@link OutboundFetchError} refusal otherwise.
 */
export function admitUrl(
	input: string,
	policy: OutboundPolicy,
	source: OutboundUrlSource,
): AdmittedDestination {
	let url: URL;
	try {
		url = new URL(input);
	} catch {
		throw new OutboundFetchError("url_unparseable");
	}
	const plaintext = url.protocol === "http:";
	if (url.protocol !== "https:" && !plaintext) throw new OutboundFetchError("scheme_not_allowed");
	const host = urlHost(url);
	if (host === undefined) throw new OutboundFetchError("url_unparseable");
	const internal = source === "registration" && matchesHostList(policy.internalHosts, host);
	if (plaintext && !(internal && isLoopbackHostname(host))) {
		throw new OutboundFetchError("scheme_not_allowed", host);
	}
	if (url.username !== "" || url.password !== "") {
		throw new OutboundFetchError("userinfo_present", host);
	}
	if (BAD_PORTS.has(url.port)) throw new OutboundFetchError("port_not_allowed", host);
	if (matchesHostList(policy.deniedHosts, host)) {
		throw new OutboundFetchError("host_not_allowed", host);
	}
	if (policy.allowedHosts.length > 0 && !matchesHostList(policy.allowedHosts, host)) {
		throw new OutboundFetchError("host_not_allowed", host);
	}
	const literal = host.startsWith("[") ? host.slice(1, -1) : isIP(host) === 4 ? host : undefined;
	const destination = { url, host, literal, internal, plaintext };
	if (literal !== undefined) admitAddresses(destination, [literal]);
	return destination;
}

/**
 * Whether `addresses`, every address the destination's host resolved to,
 * may be connected to: each an IP address; none special-use unless the host
 * is internal (a mixed answer is refused: no address is picked from it);
 * each loopback for plain http. Throws an {@link OutboundFetchError} otherwise.
 */
export function admitAddresses(
	destination: AdmittedDestination,
	addresses: readonly string[],
): void {
	if (addresses.length === 0 || addresses.some((address) => isIP(address) === 0)) {
		throw new OutboundFetchError("resolution_failed", destination.host);
	}
	if (!destination.internal && addresses.some(isSpecialUseAddress)) {
		throw new OutboundFetchError("special_use_address", destination.host);
	}
	if (destination.plaintext && !addresses.every(isLoopbackHostname)) {
		throw new OutboundFetchError("scheme_not_allowed", destination.host);
	}
}
