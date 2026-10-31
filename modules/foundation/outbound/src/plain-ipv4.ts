/** The plain pairs whose name outbound resolves to IPv4 addresses alone. */
import { type Admitted, type HostEntry, hostEntryOf, withinHosts } from "@mod/outbound-policy";
import { z } from "zod";

/** A pair as the plain lists read one: its host and its port. */
const pairOf = (pair: string) => hostEntryOf(pair, { port: true });

/** A read pair's host, as the lists spell it. */
const hostOf = (read: HostEntry) => (read.kind === "address" ? read.address : read.name);

/** Whether two pairs name one host and port, the hosts compared as the policy's lists compare them. */
const samePair = (a: string, b: string) => {
	const [x, y] = [pairOf(a), pairOf(b)];
	return x !== undefined && y !== undefined && x.port === y.port && hostOf(x) === hostOf(y);
};

/** The pairs of `plain-ipv4` that read as pairs: one that does not is refused at its place alone. */
const readIn = (s: PlainLists) => s["plain-ipv4"].filter((pair) => pairOf(pair) !== undefined);

export const plainIpv4Setting = z
	.array(z.string().refine((pair) => pairOf(pair) !== undefined, "not a host:port pair"))
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
			readIn(s).every((pair) =>
				[...s["plain-loopback"], ...s["plain-internal"]].some((plain) => samePair(pair, plain)),
			),
		"plain-ipv4 names only pairs plain-loopback or plain-internal names",
	],
	[
		(s) => !readIn(s).some((pair) => pairOf(pair)?.kind === "address"),
		"plain-ipv4 names hosts by name: an address is reached as written, never resolved",
	],
	[
		(s) => !readIn(s).some((pair, i, all) => all.findIndex((other) => samePair(pair, other)) !== i),
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
		const read = pairOf(pair);
		return read?.port === admitted.port && withinHosts(admitted.url.href, [hostOf(read)]);
	});
