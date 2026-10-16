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

/** The trusted proxies and the hops through them, as an operator's section takes them. */
export const sourceSettings = z.strictObject({
	"trusted-proxies": z
		.array(block)
		.default([])
		.describe(
			"Proxies whose forwarded headers are believed: IPs without a zone, or CIDRs with one prefix length in decimal without a leading zero. Always set behind a proxy: otherwise every request's source is the proxy, and all look like one source.",
		),
	"proxy-hops": z
		.number()
		.int()
		.min(1)
		.max(10)
		.default(1)
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
	const trusted = new BlockList();
	for (const entry of settings["trusted-proxies"]) {
		const read = blockOf(entry);
		if (!read) throw new TypeError("not a trusted proxy entry; the section's schema refuses it");
		const { address, family, prefix } = read;
		const type = family === 6 ? "ipv6" : "ipv4";
		if (prefix === undefined) trusted.addAddress(address, type);
		else trusted.addSubnet(address, prefix, type);
	}
	return Object.freeze({
		trusted,
		hops: settings["proxy-hops"],
		...(certificate ? { certificate } : {}),
	});
}
