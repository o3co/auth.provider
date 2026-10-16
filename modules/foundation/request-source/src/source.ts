import { isIP } from "node:net";
import { certificateOf } from "@mod/client-certificate";
import type { Source } from "./contract.ts";
import type { TrustedProxies } from "./settings.ts";

/** The address without its port: `[v6]:port` or `v4:port`; anything else as it is. */
function withoutPort(text: string): string {
	const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(text);
	if (bracketed) return bracketed[1] ?? "";
	return /^\d+\.\d+\.\d+\.\d+:\d{1,5}$/.test(text) ? text.slice(0, text.lastIndexOf(":")) : text;
}

/**
 * One address in its canonical form (lower case, zeros compressed, IPv4-mapped IPv6 as IPv4,
 * no zone), from a bare address or one with a port; undefined for anything else.
 */
export function canonical(text: string): string | undefined {
	const host = withoutPort(text.trim()).replace(/%.*$/, "");
	const family = isIP(host);
	if (family === 4) return host;
	if (family !== 6) return undefined;
	const compressed = new URL(`http://[${host}]`).hostname.slice(1, -1);
	const v4 = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(compressed);
	if (!v4) return compressed;
	const [high, low] = [Number.parseInt(v4[1] ?? "", 16), Number.parseInt(v4[2] ?? "", 16)];
	return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

export const trusts = (proxies: TrustedProxies, address: string | undefined) =>
	address !== undefined && proxies.trusted.check(address, isIP(address) === 6 ? "ipv6" : "ipv4");

/**
 * The sender, walking the forwarded chain from the peer while each address is a trusted proxy,
 * at most `hops` times. When the walk ends on a trusted proxy, the sender is not determined.
 * The scheme comes from a single forwarded value, and only from a trusted peer.
 */
export function sourceOf(
	proxies: TrustedProxies,
	peer: string,
	headers: ReadonlyMap<string, string>,
): Source {
	const direct = canonical(peer) ?? peer;
	const chain = (headers.get("x-forwarded-for") ?? "").split(",").filter((s) => s.trim() !== "");
	let address = direct;
	for (let hop = 0; hop < proxies.hops && trusts(proxies, address); hop++) {
		const next = canonical(chain.pop() ?? "");
		if (next === undefined) break;
		address = next;
	}
	const fromProxy = trusts(proxies, direct);
	const proto = headers.get("x-forwarded-proto")?.trim().toLowerCase();
	const scheme = fromProxy && (proto === "http" || proto === "https") ? proto : "http";
	const forwarded =
		proxies.certificate && fromProxy ? certificateOf(headers, proxies.certificate) : undefined;
	const clientCertificate = forwarded?.kind === "none" ? undefined : forwarded;
	return Object.freeze({
		address,
		scheme,
		determined: !trusts(proxies, address),
		...(clientCertificate ? { clientCertificate } : {}),
	});
}
