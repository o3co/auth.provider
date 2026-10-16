import { type AreaScene, area, sceneOf } from "@mod/conformance";
import { type KeysPart, keysArea } from "@mod/conformance-keys";
import { type ClientScene, oauthArea } from "@mod/conformance-oauth";

/** Tokens bound to the client's certificate, as a trusted proxy forwards it. */
export interface MtlsPart {
	/** The header the proxy forwards the certificate in: one PEM block, URL-encoded, or Envoy's XFCC. */
	readonly header: { readonly dialect: "pem" | "xfcc"; readonly name: string };
	/** The peers trusted to forward it (addresses). */
	readonly trustedProxies: readonly string[];
	/**
	 * Any certificate that parses binds, unless these anchors (PEM) are given: then only a path to one
	 * of them, its revocation checked by CRL, OCSP or both from these sources (`host:port`) when they
	 * are given.
	 */
	readonly pki?: {
		readonly anchors: readonly string[];
		readonly revocation?: {
			readonly mode: "crl" | "ocsp" | "both";
			readonly onUnavailable: "reject" | "allow";
			readonly sources: readonly string[];
		};
	};
}

export const mtlsArea = area<MtlsPart>("mtls");

/** An mTLS scene: keys, clients at the token endpoint with introspection, and the mTLS part. */
export function mtlsScene(
	scene: MtlsPart & {
		readonly issuer: string;
		readonly keys: KeysPart;
		readonly clients: readonly ClientScene[];
		readonly dpop?: boolean;
	},
): AreaScene {
	const { issuer, keys, clients, dpop, ...part } = scene;
	return sceneOf(
		keysArea.part(keys),
		oauthArea.part({ issuer, clients, introspection: true, ...(dpop ? { dpop } : {}) }),
		mtlsArea.part(part),
	);
}
