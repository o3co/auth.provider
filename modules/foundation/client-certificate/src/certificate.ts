import type { CertificateHeaders, ForwardedCertificate } from "./contract.ts";
import { base64, certificateBlocks } from "./pem.ts";
import { xfccOf } from "./xfcc.ts";

export type CertificateRead = { readonly kind: "none" } | ForwardedCertificate;

const malformed: CertificateRead = Object.freeze({ kind: "malformed" });

/** The certificate as a request hands it on: copied out of the Buffers, frozen. */
const certificate = (leaf: Uint8Array, chain: readonly Uint8Array[]): CertificateRead =>
	Object.freeze({
		kind: "certificate",
		leaf: new Uint8Array(leaf),
		chain: Object.freeze(chain.map((part) => new Uint8Array(part))),
	});

const rawLimit = 16_384;

/** One structured-field byte sequence (`:base64:`). */
const byteSequence = (item: string) => {
	const found = /^:([A-Za-z0-9+/=]*):$/.exec(item.trim());
	return found?.[1] && base64.test(found[1]) ? Buffer.from(found[1], "base64") : undefined;
};

/** The one certificate block of a PEM text that holds nothing else. */
function pemBlock(text: string) {
	const blocks = certificateBlocks(text);
	return blocks?.length === 1 ? blocks[0] : undefined;
}

/**
 * The client certificate a trusted proxy forwards, decoded from its transport form only: what the
 * certificate holds, and whether it is any good, is for its reader to judge.
 */
export function certificateOf(
	headers: ReadonlyMap<string, string>,
	at: CertificateHeaders,
): CertificateRead {
	const leafText = headers.get(at.header);
	if (leafText === undefined) return { kind: "none" };
	const chainText = at["chain-header"] ? headers.get(at["chain-header"]) : undefined;
	if (leafText.length > rawLimit || (chainText?.length ?? 0) > rawLimit) return malformed;
	if (at.dialect === "xfcc") {
		const found = xfccOf(leafText);
		return found ? certificate(found.leaf, found.chain) : malformed;
	}
	const leaf = at.dialect === "rfc9440" ? byteSequence(leafText) : pemBlock(leafText);
	const chain = chainText?.split(",").map(byteSequence) ?? [];
	const whole = <T extends Uint8Array>(part: T | undefined): part is T => (part?.length ?? 0) > 0;
	return whole(leaf) && chain.every(whole) ? certificate(leaf, chain) : malformed;
}
