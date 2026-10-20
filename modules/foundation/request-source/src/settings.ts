import { BlockList, isIP } from "node:net";
import type { CertificateHeaders } from "@mod/client-certificate";
import { z } from "zod";

/** A trusted proxy entry: an IP address with no zone, and a prefix length when a CIDR block. */
function blockOf(entry: string) {
	const found = /^([^/%]+)(?:\/(0|[1-9]\d{0,2}))?$/.exec(entry);
	const address = found?.[1] ?? "";
	const family = isIP(address);
	const prefix = found?.[2] === undefined ? undefined : Number(found[2]);
	const fits = prefix === undefined || prefix <= (family === 4 ? 32 : 128);
	return found && family !== 0 && fits ? { address, family, prefix } : undefined;
}

const block = z.string().refine((s) => blockOf(s) !== undefined, "an IP address or CIDR");

/** A setting holding IP addresses without a zone, or CIDR blocks, as `trusted-proxies` takes them. */
export const addressList = () => z.array(block);

/** Addresses a setting lists, to ask of a canonical address. */
export interface AddressList {
	has(address: string): boolean;
}

/** The block list of entries a schema took. */
function blockListOf(entries: readonly string[], what: string) {
	const list = new BlockList();
	for (const entry of entries) {
		const read = blockOf(entry);
		if (!read) throw new TypeError(`not ${what}; the section's schema refuses it`);
		const { address, family, prefix } = read;
		const type = family === 6 ? "ipv6" : "ipv4";
		if (prefix === undefined) list.addAddress(address, type);
		else list.addSubnet(address, prefix, type);
	}
	return list;
}

/**
 * Whether one entry covers a whole family: one block holding both ends of a family holds all of it.
 * An IPv4-mapped block (`::ffff:0:0/96`, or any holding it) covers every IPv4 address, as a mapped
 * peer is checked as IPv4.
 */
function coversAFamily(entry: string) {
	const one = blockListOf([entry], "a trusted proxy");
	const both = (type: "ipv4" | "ipv6", low: string, high: string) =>
		one.check(low, type) && one.check(high, type);
	return (
		both("ipv4", "0.0.0.0", "255.255.255.255") ||
		both("ipv6", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	);
}

/** An IPv4 address as a number. */
const ipv4Number = (address: string) =>
	address.split(".").reduce((n, part) => (n << 8n) | BigInt(Number(part)), 0n);

/** An IPv6 address as a number, `::` and a dotted IPv4 tail written out. */
function ipv6Number(address: string): bigint {
	const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(address)?.[1];
	const hex = tail
		? `${address.slice(0, -tail.length)}${(ipv4Number(tail) >> 16n).toString(16)}:${(ipv4Number(tail) & 0xffffn).toString(16)}`
		: address;
	const [head = "", rest] = hex.split("::");
	const before = head === "" ? [] : head.split(":");
	const after = rest === undefined || rest === "" ? [] : rest.split(":");
	const groups =
		rest === undefined
			? before
			: [...before, ...Array(8 - before.length - after.length).fill("0"), ...after];
	return groups.reduce((n, group) => (n << 16n) | BigInt(Number.parseInt(group, 16)), 0n);
}

/** Where IPv4 lies inside IPv6: the mapped addresses, `::ffff:0:0/96`, as a mapped peer is checked as IPv4. */
const mapped = { start: 0xffff_0000_0000n, end: 0xffff_ffff_ffffn };

/** Whether intervals together cover every number from 0 to `last`. */
function coverAll(intervals: readonly { start: bigint; end: bigint }[], last: bigint): boolean {
	let reached = -1n;
	for (const { start, end } of intervals.toSorted((a, b) => (a.start < b.start ? -1 : 1))) {
		if (start > reached + 1n) return false;
		if (end > reached) reached = end;
	}
	return reached >= last;
}

/**
 * Whether entries together cover a whole family: their blocks, as intervals, leave no address of
 * IPv4 or of IPv6 out. An IPv6 block's share of the mapped addresses counts as IPv4 too. Both ends
 * of a family held tells nothing of a union, so the intervals are joined; an entry covering a family
 * alone is left to its own refusal.
 */
function coverAFamilyTogether(entries: readonly string[]): boolean {
	const v4: { start: bigint; end: bigint }[] = [];
	const v6: { start: bigint; end: bigint }[] = [];
	for (const entry of entries) {
		const read = blockOf(entry);
		// One that covers a family alone is refused at its own place.
		if (!read || coversAFamily(entry)) continue;
		const bits = read.family === 4 ? 32n : 128n;
		const host = bits - BigInt(read.prefix ?? Number(bits));
		const value = read.family === 4 ? ipv4Number(read.address) : ipv6Number(read.address);
		const start = (value >> host) << host;
		const end = start | ((1n << host) - 1n);
		if (read.family === 4) v4.push({ start, end });
		else {
			v6.push({ start, end });
			const low = start > mapped.start ? start : mapped.start;
			const high = end < mapped.end ? end : mapped.end;
			if (low <= high) v4.push({ start: low - mapped.start, end: high - mapped.start });
		}
	}
	return coverAll(v4, (1n << 32n) - 1n) || coverAll(v6, (1n << 128n) - 1n);
}

/** The addresses entries a schema took (by `addressList`) list: whether an address is among them. */
export function addressesOf(entries: readonly string[]): AddressList {
	const list = blockListOf(entries, "an address list entry");
	return Object.freeze({
		has: (address: string) => {
			const family = isIP(address);
			return family !== 0 && list.check(address, family === 6 ? "ipv6" : "ipv4");
		},
	});
}

/** The trusted proxies and the hops through them, as an operator's section takes them. */
export const sourceSettings = z.strictObject({
	"trusted-proxies": z
		.array(
			// A proxy trusted at every address would make every client a proxy, so no source is ever told.
			block.refine(
				(s) => blockOf(s) === undefined || !coversAFamily(s),
				"a block covering every address of a family (/0, or every IPv4 address mapped into IPv6): every source would be undetermined; list the proxies' own addresses",
			),
		)
		.refine(
			(entries) => !coverAFamilyTogether(entries),
			"entries that together cover every address of a family: every source would be undetermined; list the proxies' own addresses",
		)
		.prefault([])
		.describe(
			"Proxies whose forwarded headers are believed: IPs without a zone, or CIDRs with one prefix length in decimal without a leading zero. Always set behind a proxy: otherwise every request's source is the proxy, and all look like one source.",
		),
	"proxy-hops": z
		.number()
		.int()
		.min(1)
		.max(10)
		.prefault(1)
		.describe("How many trusted proxies, at most, a request passes through."),
});

export type SourceSettings = z.output<typeof sourceSettings>;

export interface TrustedProxies {
	readonly trusted: BlockList;
	readonly hops: number;
	/** Where a trusted proxy forwards the client's certificate; none read without it. */
	readonly certificate?: CertificateHeaders;
}

/** The trusted proxies, from settings the schema took, and where they forward the client's certificate. */
export function proxiesOf(
	settings: SourceSettings,
	certificate?: CertificateHeaders,
): TrustedProxies {
	const trusted = blockListOf(settings["trusted-proxies"], "a trusted proxy entry");
	return Object.freeze({
		trusted,
		hops: settings["proxy-hops"],
		...(certificate ? { certificate } : {}),
	});
}
