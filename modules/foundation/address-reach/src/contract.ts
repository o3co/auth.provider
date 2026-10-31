import { BlockList, isIP } from "node:net";
import { isLoopbackName } from "@mod/url-setting";

const blockList = (family: "ipv4" | "ipv6", subnets: readonly (readonly [string, number])[]) => {
	const list = new BlockList();
	for (const [net, bits] of subnets) list.addSubnet(net, bits, family);
	return list;
};
// IANA's special-purpose blocks, and IPv6 outside global unicast; and Azure's platform address,
// public but the host node's in every region (WireServer, its DNS and DHCP). A BlockList checks
// IPv4-mapped IPv6 against IPv4 rules too.
const specialIpv4 = blockList("ipv4", [
	["168.63.129.16", 32],
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
// Private networks; the cloud metadata addresses inside them are not.
const privately = {
	ipv4: blockList("ipv4", [
		["10.0.0.0", 8],
		["100.64.0.0", 10],
		["172.16.0.0", 12],
		["192.168.0.0", 16],
	]),
	ipv6: blockList("ipv6", [["fc00::", 7]]),
};
// The cloud metadata and credential addresses inside the private networks: Alibaba Cloud's, and over
// IPv6 AWS's (the instance's, and EKS Pod Identity's credentials), Google Cloud's, Akamai Cloud's
// (Linode), Scaleway's and Oracle Cloud's. Those over IPv4 elsewhere sit in special-purpose blocks,
// never private: link-local (169.254.0.0/16) for most, 192.0.0.0/24 for Oracle Cloud Classic's.
const metadata = { ipv4: new BlockList(), ipv6: new BlockList() };
metadata.ipv4.addAddress("100.100.100.200", "ipv4");
metadata.ipv6.addAddress("fd00:ec2::254", "ipv6");
metadata.ipv6.addAddress("fd00:ec2::23", "ipv6");
metadata.ipv6.addAddress("fd20:ce::254", "ipv6");
metadata.ipv6.addAddress("fd00:a9fe:a9fe::1", "ipv6");
metadata.ipv6.addAddress("fd00:42::42", "ipv6");
metadata.ipv6.addAddress("fd00:c1::a9fe:a9fe", "ipv6");

const familyOf = (address: string) => (isIP(address) === 6 ? "ipv6" : "ipv4");
const inList = (lists: Record<"ipv4" | "ipv6", BlockList>, address: string) =>
	lists[familyOf(address)].check(address, familyOf(address));
const unbracketed = (host: string) => host.replace(/^\[(.*)\]$/, "$1");

/** Whether an IP address is special-purpose: IANA's blocks not globally reachable, multicast, IPv6 outside global unicast, Azure's platform address. */
export const isSpecialAddress = (address: string): boolean =>
	familyOf(address) === "ipv6"
		? !globalUnicast.check(address, "ipv6") || specialInGlobalUnicast.check(address, "ipv6")
		: specialIpv4.check(address, "ipv4");

/** The IPv4 address an IPv6 address in canonical form carries (mapped, translated or compatible), if any. */
export function carriedIPv4(address: string): string | undefined {
	const found = /^::(?:ffff:(?:0:)?)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
	if (!found) return undefined;
	const [high, low] = [Number.parseInt(found[1] ?? "", 16), Number.parseInt(found[2] ?? "", 16)];
	return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

/**
 * An IP address as a connection reaches it, unbracketed and IPv6 in canonical form: an IPv4 address
 * mapped into IPv6 is that IPv4 one, but no other IPv6 form that carries one (compatible, translated).
 */
export function reachedAddress(address: string): string {
	const bare = unbracketed(address);
	if (isIP(bare) !== 6) return bare;
	const written = unbracketed(URL.parse(`https://[${bare}]`)?.hostname ?? "");
	return /^::ffff:[0-9a-f]{1,4}:[0-9a-f]{1,4}$/.test(written)
		? (carriedIPv4(written) ?? written)
		: written;
}

/** Whether an IP address, as a connection reaches it, is private: 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7, but a cloud metadata address. */
export const isPrivateAddress = (address: string): boolean => {
	const spelled = reachedAddress(address);
	return inList(privately, spelled) && !inList(metadata, spelled);
};

/**
 * Whether an IP address, however written (bracketed, in any case, IPv4 mapped into IPv6), reaches
 * loopback: 127/8 or `::1`. A name is none; nor is an IPv6 form that carries 127/8 unmapped, which no
 * connection takes to loopback. The literal is judged as url-setting's `isLoopbackName` judges it.
 */
export function isLoopbackAddress(address: string): boolean {
	const bare = address.startsWith("[") && address.endsWith("]") ? address.slice(1, -1) : address;
	const family = isIP(bare);
	if (family === 0 || (family === 4 && bare !== address)) return false;
	return isLoopbackName(address);
}
