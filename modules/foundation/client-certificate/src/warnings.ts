import type { Clock } from "@mod/kernel";
import type { CertificateHeaders, ForwardedCertificate } from "./contract.ts";

const minute = 60_000;

/**
 * Whether to warn now of a certificate header that was sent but not taken (its peer is no trusted
 * proxy): at most once a minute.
 */
export function ignoredCertificates(at: CertificateHeaders | undefined, clock: Clock) {
	let last = Number.NEGATIVE_INFINITY;
	return (headers: ReadonlyMap<string, string>, taken: ForwardedCertificate | undefined) => {
		if (!at || !headers.has(at.header) || taken) return false;
		const now = clock.now();
		if (now - last <= minute) return false;
		last = now;
		return true;
	};
}
