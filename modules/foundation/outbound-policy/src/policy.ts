import { BlockList, isIP } from "node:net";
import {
	type Admitted,
	type CredentialRefusal,
	DestinationRefused,
	type Limits,
	type Narrower,
	type Policy,
	type RefusalReason,
} from "./contract.ts";
import type { PolicySettings } from "./settings.ts";

/** The operator's rules, as read from the settings. */
export interface Rules {
	readonly allow: readonly string[];
	/** Any public address is reached, whatever `allow` names. */
	readonly anyPublic: boolean;
	readonly deny: readonly string[];
	readonly plainLoopback: readonly string[];
	/** The hosts an operator's own URL may reach at a private address. */
	readonly internal: readonly string[];
}

/** Ports the Fetch standard calls bad, and port 0. */
const badPorts = new Set([
	0, 1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102,
	103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465,
	512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993,
	995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668,
	6669, 6679, 6697, 10080,
]);

const blockList = (family: "ipv4" | "ipv6", subnets: readonly (readonly [string, number])[]) => {
	const list = new BlockList();
	for (const [net, bits] of subnets) list.addSubnet(net, bits, family);
	return list;
};
// IANA's special-purpose blocks, and IPv6 outside global unicast. A BlockList checks
// IPv4-mapped IPv6 against IPv4 rules too.
const specialIpv4 = blockList("ipv4", [
	["0.0.0.0", 8],
	["10.0.0.0", 8],
	["100.64.0.0", 10],
	["127.0.0.0", 8],
	["169.254.0.0", 16],
	["172.16.0.0", 12],
	["192.0.0.0", 24],
	["192.0.2.0", 24],
	["192.88.99.0", 24],
	["192.168.0.0", 16],
	["198.18.0.0", 15],
	["198.51.100.0", 24],
	["203.0.113.0", 24],
	["224.0.0.0", 4],
	["240.0.0.0", 4],
]);
const globalUnicast = blockList("ipv6", [["2000::", 3]]);
const specialInGlobalUnicast = blockList("ipv6", [
	["2001::", 23],
	["2001:db8::", 32],
	["2002::", 16],
	["3fff::", 20],
]);
// Private networks an operator's own hosts may reach; the cloud metadata addresses inside them are not.
const privately = {
	ipv4: blockList("ipv4", [
		["10.0.0.0", 8],
		["100.64.0.0", 10],
		["172.16.0.0", 12],
		["192.168.0.0", 16],
	]),
	ipv6: blockList("ipv6", [["fc00::", 7]]),
};
// Alibaba Cloud's, AWS's over IPv6, Google Cloud's over IPv6; the others sit in link-local, never reached.
const metadata = { ipv4: new BlockList(), ipv6: new BlockList() };
metadata.ipv4.addAddress("100.100.100.200", "ipv4");
metadata.ipv6.addAddress("fd00:ec2::254", "ipv6");
metadata.ipv6.addAddress("fd20:ce::254", "ipv6");
const loopback = { ipv4: new BlockList(), ipv6: new BlockList() };
loopback.ipv4.addSubnet("127.0.0.0", 8, "ipv4");
loopback.ipv6.addAddress("::1", "ipv6");

const familyOf = (address: string) => (isIP(address) === 6 ? "ipv6" : "ipv4");
const inList = (lists: Record<"ipv4" | "ipv6", BlockList>, address: string) =>
	lists[familyOf(address)].check(address, familyOf(address));
const isSpecial = (address: string) =>
	familyOf(address) === "ipv6"
		? !globalUnicast.check(address, "ipv6") || specialInGlobalUnicast.check(address, "ipv6")
		: specialIpv4.check(address, "ipv4");

/** The IPv4 address an IPv6 address carries (mapped, translated or compatible), if any. */
function carried(address: string): string | undefined {
	const found = /^::(?:ffff:(?:0:)?)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
	if (!found) return undefined;
	const [high, low] = [Number.parseInt(found[1] ?? "", 16), Number.parseInt(found[2] ?? "", 16)];
	return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

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
	return carried(name) ?? name;
}

const isHost = (host: string) =>
	(isIP(unbracketed(host)) === 6 || !/[*:/?#@\\]/.test(host)) && normalized(host) !== undefined;

/** Whether an operator's entry is a host, or `.name` for the name and every name under it. */
export const isHostEntry = (entry: string) =>
	entry.startsWith(".") ? isListEntry(entry) : isHost(entry);

const splitPair = (pair: string) => {
	const at = pair.lastIndexOf(":");
	return { host: pair.slice(0, at), port: pair.slice(at + 1) };
};

/** A host and a port; the port is matched as written, so only its canonical form can be taken. */
export function isPair(pair: string): boolean {
	const { host, port } = splitPair(pair);
	return /^[1-9][0-9]{0,4}$/.test(port) && Number(port) <= 65_535 && isHost(host);
}

const pairOf = (pair: string) => {
	const { host, port } = splitPair(pair);
	return `${normalized(host)}:${port}`;
};

/** An operator's host list entry: a name, `.name` for it and every name under it, or an address. */
export type HostEntry =
	| { readonly kind: "name"; readonly name: string; readonly under: boolean }
	| { readonly kind: "address"; readonly address: string };

const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** An entry read as written, correcting only case and Unicode: `10.5`, a trailing dot or `_` is none. */
export function hostEntryOf(entry: string): HostEntry | undefined {
	const bare = unbracketed(entry);
	const family = isIP(bare);
	if (family === 6 || (family === 4 && bare === entry)) {
		return { kind: "address", address: normalized(bare) ?? bare };
	}
	const under = entry.startsWith(".");
	const name = under ? entry.slice(1) : entry;
	if (/[^\p{L}\p{N}.-]/u.test(name)) return undefined;
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

/** Checks a URL before any name is resolved; `signed` material takes plain http at the caller's hosts. */
export function admitUrl(
	raw: string,
	policy: Rules,
	narrower: Narrower = {},
	signed = false,
): Admitted {
	const url = URL.parse(raw);
	if (!url || (url.protocol !== "https:" && url.protocol !== "http:")) {
		throw new DestinationRefused("scheme");
	}
	if (url.username !== "" || url.password !== "") throw new DestinationRefused("userinfo");
	const port = url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
	if (badPorts.has(port)) throw new DestinationRefused("port");
	const host = normalized(url.hostname);
	if (host === undefined || matches(host, policy.deny)) throw new DestinationRefused("denied");
	if (!policy.anyPublic && !matches(host, policy.allow)) {
		throw new DestinationRefused("not-allowed");
	}
	// Signed material always names its hosts, none meaning none; other callers narrow when they name some.
	if ((signed || narrower.hosts) && !matches(host, narrower.hosts ?? [])) {
		throw new DestinationRefused("not-allowed");
	}
	const plain = url.protocol === "http:";
	const loopback = plain && policy.plainLoopback.some((pair) => pairOf(pair) === `${host}:${port}`);
	if (plain && !loopback && !signed) throw new DestinationRefused("scheme");
	// Named by its configured URL, the operator's own reach ends at that URL's origin.
	const own =
		narrower.internal !== undefined && URL.parse(narrower.internal)?.origin === url.origin;
	const internal = own && listed(host, policy.internal);
	return { url, host, port, plain, loopback, internal };
}

const isPrivate = (address: string) => {
	const spelled = normalized(address) ?? address;
	return inList(privately, spelled) && !inList(metadata, spelled);
};

/** What refuses an address by reach: all but loopback (carried in IPv6 too) for a plain pair; special but private ones for an internal host. */
function refusing(reach: Pick<Admitted, "loopback" | "internal">): (address: string) => boolean {
	if (reach.loopback) return (address) => !inList(loopback, normalized(address) ?? address);
	if (reach.internal) return (address) => isSpecial(address) && !isPrivate(address);
	return isSpecial;
}

/**
 * One special-purpose address refuses them all; a named plain pair reaches loopback alone, and an
 * internal host private addresses too.
 */
export function admitAddresses(
	addresses: readonly string[],
	reach: Pick<Admitted, "loopback" | "internal">,
): readonly string[] {
	if (addresses.length === 0 || addresses.some(refusing(reach))) {
		throw new DestinationRefused("special-address");
	}
	return addresses;
}

/**
 * What an operator sets, or writes otherwise, so the policy lets a URL it refused for `reason`
 * through; it names keys alone, never the URL's host, port or any other value.
 */
export function remedyOf(
	reason: RefusalReason,
	raw: string,
	policy: Pick<Rules, "allow" | "anyPublic">,
	narrower: Narrower = {},
): string {
	const url = URL.parse(raw);
	switch (reason) {
		case "not-allowed": {
			const host = url ? normalized(url.hostname) : undefined;
			return !policy.anyPublic && !matches(host ?? "", policy.allow)
				? "name the host in outbound.allow, or set outbound.allow-any-public"
				: "the host is not one the setting may reach";
		}
		case "scheme":
			return url?.protocol === "http:"
				? "plain http reaches only a host:port that outbound.plain-loopback names; otherwise write the URL with https"
				: "only https and http URLs are reached";
		case "userinfo":
			return "write the URL without a user or password";
		case "port":
			return "the URL's port is one outbound never reaches";
		case "denied":
			return "the host matches outbound.deny";
		case "special-address":
			return narrower.internal
				? "the URL names a special-purpose address; a private one is reached only when outbound.internal-hosts names its host"
				: "the URL names a special-purpose address, which outbound never reaches";
		case "redirect":
			return "a redirect is never followed";
		case "credential":
			return "a credential never goes with material fetched for its signature";
	}
}

/** Why a credential must not go to these URLs: more than one origin, or one neither https nor a named plain-loopback pair. */
export function credentialRefusal(
	urls: readonly string[],
	plainLoopback: readonly string[],
): CredentialRefusal | undefined {
	const parsed = urls.map((raw) => URL.parse(raw));
	const named = (url: URL) => {
		const port = url.port === "" ? 80 : Number(url.port);
		return plainLoopback.some((pair) => pairOf(pair) === `${normalized(url.hostname)}:${port}`);
	};
	const sent = (url: URL | null) =>
		url?.protocol === "https:" || (url?.protocol === "http:" && named(url));
	if (!parsed.every(sent)) return "scheme";
	return new Set(parsed.map((url) => url?.origin)).size > 1 ? "origins" : undefined;
}

/** A narrower's number, which only a caller's mistake makes other than positive and finite. */
const narrowing = (value: number | undefined): number => {
	if (value === undefined) return Number.POSITIVE_INFINITY;
	if (value > 0 && Number.isFinite(value)) return value;
	throw new RangeError("outbound: a narrower's numbers are positive and finite");
};

/** The operator's destination policy and caps, as the settings give them, for sending and for boot alike. */
export function policyOf(settings: PolicySettings): Policy {
	const rules: Rules = {
		allow: settings.allow,
		anyPublic: settings["allow-any-public"],
		deny: settings.deny,
		plainLoopback: settings["plain-loopback"],
		internal: settings["internal-hosts"],
	};
	const limitsOf = (narrower: Narrower = {}, signed = false): Limits => ({
		maxBytes: Math.min(
			settings[signed ? "signed-max-response-size" : "max-response-size"],
			narrowing(narrower.maxBytes),
		),
		timeoutMs: Math.min(settings.timeout, narrowing(narrower.timeoutMs)),
	});
	/** Why the policy refuses the URL, or undefined when it lets it through; no name is resolved. */
	const refusalOf = (url: string, narrower: Narrower): RefusalReason | undefined => {
		try {
			const admitted = admitUrl(url, rules, narrower, false);
			// An address written in the URL is checked now; a name's, once resolved, when sent.
			if (isIP(admitted.host) !== 0) admitAddresses([admitted.host], admitted);
			return undefined;
		} catch (error) {
			if (error instanceof DestinationRefused) return error.reason;
			throw error;
		}
	};
	return {
		admit: (url, narrower = {}, signed = false) => admitUrl(url, rules, narrower, signed),
		admitAddresses,
		explain: (url, narrower = {}) => {
			const reason = refusalOf(url, narrower);
			return reason && `${reason}: ${remedyOf(reason, url, rules, narrower)}`;
		},
		credentialRefusal: (urls) => credentialRefusal(urls, rules.plainLoopback),
		listed,
		limitsOf,
	};
}
