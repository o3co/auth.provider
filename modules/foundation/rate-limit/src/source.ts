/** IPv4 sources by address; IPv6 sources by their /64, which one holder usually has whole. */
export function sourceKey(address: string): string {
	if (!address.includes(":")) return address;
	const [head = "", tail = ""] = address.split("::");
	const left = head ? head.split(":") : [];
	const right = tail ? tail.split(":") : [];
	const groups = address.includes("::")
		? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right]
		: left;
	return `${groups.slice(0, 4).join(":")}::/64`;
}
