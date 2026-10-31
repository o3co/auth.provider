import { isIP } from "node:net";
import { carriedIPv4 } from "@mod/address-reach";
import { z } from "zod";

const unbracketed = (host: string) => host.replace(/^\[(.*)\]$/, "$1");

/**
 * One spelling for a host, so allow, deny and a caller's hosts compare alike: lowercase, punycode,
 * canonical IP forms, no trailing dot, an IPv4 address carried in IPv6 as the IPv4 one.
 */
export function normalized(host: string): string | undefined {
	const bracketed = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
	const parsed = URL.parse(`https://${bracketed}`);
	if (!parsed) return undefined;
	const name = unbracketed(parsed.hostname).replace(/\.$/, "");
	if (name === "" || name.split(".").includes("")) return undefined;
	return carriedIPv4(name) ?? name;
}

const splitPair = (pair: string) => {
	const at = pair.lastIndexOf(":");
	return { host: pair.slice(0, at), port: pair.slice(at + 1) };
};

/** A pair spelled one way: its host as `normalized` spells hosts, its port as written. */
export const pairOf = (pair: string) => {
	const { host, port } = splitPair(pair);
	return `${normalized(host)}:${port}`;
};

/** An operator's host list entry: a name, `.name` for it and every name under it, or an address; read as a pair, with its port. */
export type HostEntry = (
	| { readonly kind: "name"; readonly name: string; readonly under: boolean }
	| { readonly kind: "address"; readonly address: string }
) & { readonly port?: number };

const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * An entry read as written, correcting only case and Unicode: `10.5`, a trailing dot or `_` is none.
 * Taking a port, a `host:port` pair: its host read so, never `.name`, an IPv6 address in brackets
 * alone; its port 1–65535 without a leading zero, as written.
 */
export function hostEntryOf(
	entry: string,
	takes: { readonly port?: boolean } = {},
): HostEntry | undefined {
	if (takes.port) {
		const { host, port } = splitPair(entry);
		if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65_535 || isIP(host) === 6) {
			return undefined;
		}
		const read = hostEntryOf(host);
		if (read === undefined || (read.kind === "name" && read.under)) return undefined;
		return { ...read, port: Number(port) };
	}
	const bare = unbracketed(entry);
	const family = isIP(bare);
	if (family === 6 || (family === 4 && bare === entry)) {
		// An address with no canonical form, such as one with a zone, is none: no request reaches it.
		const address = normalized(bare);
		return address === undefined ? undefined : { kind: "address", address };
	}
	const under = entry.startsWith(".");
	const name = under ? entry.slice(1) : entry;
	// Letters with the marks that write them, digits, dots, hyphens and the joiners; the URL parser
	// (IDNA) refuses a joiner its script does not allow, and a mark leading a label.
	if (/[^\p{L}\p{M}\p{N}.\-\u200C\u200D]/u.test(name)) return undefined;
	// A mark the URL parser drops (a variation selector, U+034F, a Mongolian FVS) reads as written without it.
	if (/(?![\u200C\u200D])\p{Default_Ignorable_Code_Point}/u.test(name)) return undefined;
	const ascii = URL.parse(`https://${name}/`)?.hostname;
	if (ascii === undefined || isIP(ascii) !== 0) return undefined;
	return ascii.split(".").every((part) => label.test(part))
		? { kind: "name", name: ascii, under }
		: undefined;
}

/** Whether an operator's list entry reads as one. */
export const isListEntry = (entry: string) => hostEntryOf(entry) !== undefined;

const isListed = (host: string, entry: HostEntry | undefined) =>
	entry?.kind === "address"
		? host === entry.address
		: entry !== undefined &&
			(host === entry.name || (entry.under && host.endsWith(`.${entry.name}`)));

/** Whether a host is listed: the same host, or a dotted name or any name under it. */
export const listed = (host: string, entries: readonly string[]) =>
	entries.some((entry) => isListed(host, hostEntryOf(entry)));

/** `.name` is read as host lists are; any other entry is the one host it spells. */
const matches = (host: string, entries: readonly string[]) =>
	entries.some((entry) =>
		entry.startsWith(".") ? isListed(host, hostEntryOf(entry)) : host === normalized(entry),
	);

/** Whether a URL's host is among the hosts, matched as a narrower's hosts are. */
export function withinHosts(raw: string, hosts: readonly string[]): boolean {
	const url = URL.parse(raw);
	return url !== null && matches(normalized(url.hostname) ?? "", hosts);
}

/** One host a setting takes from an operator: a host, or `.name` for the name and the names under it. */
export const hostEntry = z.string().refine(isListEntry, "not a host, or a name led by a dot");

/** A list of hosts an operator writes, as `hostEntry` reads each; none unless set. */
export const hostList = z.array(hostEntry).prefault([]);
