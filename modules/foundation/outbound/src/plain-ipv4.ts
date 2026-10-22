/** The plain pairs whose name outbound resolves to IPv4 addresses alone. */
import { isIP } from "node:net";
import { type Admitted, withinHosts } from "@mod/outbound-policy";
import { z } from "zod";

/** A pair's host and port, split at its last colon. */
const split = (pair: string) => {
	const at = pair.lastIndexOf(":");
	return { host: pair.slice(0, at), port: pair.slice(at + 1) };
};

/** A host alone: an IPv6 address in brackets, or no part of a URL but the host (no path, user, port, query or fragment). */
const isHostAlone = (host: string) =>
	(/^\[[0-9a-f:.]+\]$/i.test(host) || !/[*:/?#@\\]/.test(host)) &&
	URL.parse(`http://${host}/`) !== null;

/** Whether a pair reads as one: a host alone, and a port written 1–65535 without a leading zero. */
const isPair = (pair: string) => {
	const { host, port } = split(pair);
	return /^[1-9][0-9]{0,4}$/.test(port) && Number(port) <= 65_535 && isHostAlone(host);
};

/** Whether two pairs name one host and port, the hosts compared as the policy's lists compare them. */
const samePair = (a: string, b: string) => {
	const [x, y] = [split(a), split(b)];
	return x.port === y.port && withinHosts(`http://${x.host}/`, [y.host]);
};

/** Whether a pair's host is an address, in any spelling a URL reads as one (`127.1`, an integer, IPv6). */
const namesAddress = (pair: string) => {
	const hostname = URL.parse(`http://${split(pair).host}/`)?.hostname ?? "";
	return isIP(hostname.replace(/^\[(.*)\]$/, "$1")) !== 0;
};

export const plainIpv4Setting = z
	.array(z.string().refine(isPair, "not a host:port pair"))
	.prefault([])
	.describe(
		"The `host:port` pairs of `plain-loopback` or `plain-internal` whose name is resolved to IPv4 addresses alone, for plain http to that host and port: only those answers are checked and reached, and IPv6 ones are neither. For a network answering a name with an IPv4 address and an IPv6 one that does not reach, as ECS Service Connect writes both in the hosts file. Each names its host by name.",
	);

interface PlainLists {
	readonly "plain-loopback": readonly string[];
	readonly "plain-internal": readonly string[];
	readonly "plain-ipv4": readonly string[];
}

/** The section's rules for `plain-ipv4`, each with its words: none names a pair's host or port. */
export const plainIpv4Rules: readonly [(s: PlainLists) => boolean, string][] = [
	[
		(s) =>
			s["plain-ipv4"].every((pair) =>
				[...s["plain-loopback"], ...s["plain-internal"]].some((plain) => samePair(pair, plain)),
			),
		"plain-ipv4 names only pairs plain-loopback or plain-internal names",
	],
	[
		(s) => !s["plain-ipv4"].some(namesAddress),
		"plain-ipv4 names hosts by name: an address is reached as written, never resolved",
	],
	[
		(s) =>
			!s["plain-ipv4"].some(
				(pair, i, all) => all.findIndex((other) => samePair(pair, other)) !== i,
			),
		"plain-ipv4 names a pair once",
	],
];

/**
 * Whether a request's name is resolved to IPv4 alone: plain http taken as a `plain-loopback` or
 * `plain-internal` pair's, to a host and port `plain-ipv4` names, signed material so taken included.
 * Its other ports, https to it, and a request not taken as the pair's resolve every family as before.
 */
export const takesIpv4 = (pairs: readonly string[], admitted: Admitted) =>
	admitted.plain &&
	(admitted.loopback || admitted.plainInternal === true) &&
	pairs.some((pair) => {
		const { host, port } = split(pair);
		return Number(port) === admitted.port && withinHosts(admitted.url.href, [host]);
	});
