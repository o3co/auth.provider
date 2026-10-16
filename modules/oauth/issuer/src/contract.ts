import { contract, extensionPoint } from "@mod/kernel";

/** This provider's canonical name, as the operator configures it; never derived from a request. */
export interface Issuer {
	/** An http or https URL as configured: no query, fragment, userinfo or trailing /. */
	readonly url: string;
}

export const issuer = contract<Issuer>("issuer");

/** One item this authorization server names itself by; its contributor alone decides its value. */
export interface MetadataItem {
	readonly name: string;
	/** Left out of the document when undefined. */
	readonly value: unknown;
}

export const metadata = extensionPoint<MetadataItem>("issuer.metadata", {
	multiplicity: "keyed",
	keyOf: (item) => item.name,
});
