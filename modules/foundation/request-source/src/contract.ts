import type { ForwardedCertificate } from "@mod/client-certificate";

export {
	type AddressList,
	addressesOf,
	addressList,
	proxiesOf,
	type SourceSettings,
	sourceSettings,
	type TrustedProxies,
} from "./settings.ts";
export { sourceOf } from "./source.ts";
export { ignoredForwarding } from "./warnings.ts";

/** Who sent the request, as the trusted proxies decide. */
export interface Source {
	/** Canonical: lower case, zeros compressed, IPv4-mapped IPv6 as IPv4, no zone. */
	readonly address: string;
	readonly scheme: "http" | "https";
	/** False when a trusted proxy did not say who sent it; `address` is then that proxy's. */
	readonly determined: boolean;
	/** What a trusted proxy forwarded of the client's certificate. */
	readonly clientCertificate?: ForwardedCertificate;
}

/** The request's source address when it was determined; none when it is a trusted proxy's. */
export function determinedSource(request: { readonly source: Source }): string | undefined {
	return request.source.determined ? request.source.address : undefined;
}
