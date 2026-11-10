import { withinHosts } from "@mod/host-entries";
import { distributionPointsOf } from "@mod/x509-path";
import type { Certificate } from "./trust.ts";

/** The most points of one certificate fetched: CAs often name one CRL at two locations. */
const mostPoints = 2;

/** Where a certificate's CRL may be fetched from: nowhere to ask, the URLs, or why none will do. */
export type Points =
	| { readonly kind: "none" }
	| { readonly kind: "urls"; readonly urls: readonly string[] }
	| {
			readonly kind: "unconfirmed";
			readonly reason: "malformed" | "unsupported" | "https-only" | "unlisted";
	  };

/**
 * A certificate's CRL locations outbound fetches: plain http full names for every reason, by its
 * issuer, at hosts the operator lists. No extension is none to ask; one unreadable, or none such, is
 * unconfirmed.
 */
export function pointsOf(cert: Certificate, hosts: readonly string[]): Points {
	const points = distributionPointsOf(cert);
	if (points.kind !== "points") return points.kind === "none" ? points : unconfirmed("malformed");
	if (points.urls.length === 0) return unconfirmed("unsupported");
	const plain = points.urls.filter((url) => /^http:\/\//i.test(url));
	if (plain.length === 0) return unconfirmed("https-only");
	const listed = plain.filter((url) => withinHosts(url, hosts));
	if (listed.length === 0) return unconfirmed("unlisted");
	return { kind: "urls", urls: listed.slice(0, mostPoints) };
}

const unconfirmed = (reason: Extract<Points, { kind: "unconfirmed" }>["reason"]) =>
	({ kind: "unconfirmed", reason }) as const;
