import { isUnavailable } from "@mod/kernel";
import { DestinationRefused, type SignedNarrower, type SignedOutbound } from "@mod/outbound";
import type { Fetched, Sources } from "./pki/contract.ts";

/**
 * Revocation sources over signed outbound: a server failing or no answer in time and size is an
 * outage; a destination not allowed, or any other answer, is a refusal.
 */
export function sourcesOver(
	outbound: SignedOutbound,
	reach: SignedNarrower,
	runtime: { now(): number; random(n: number): Uint8Array },
): Sources {
	const fetch = async (url: string, body?: Uint8Array): Promise<Fetched> => {
		const request = body
			? {
					method: "POST" as const,
					headers: {
						"content-type": "application/ocsp-request",
						accept: "application/ocsp-response",
					},
					body,
				}
			: { method: "GET" as const };
		try {
			const answer = await outbound.fetch(url, request, reach);
			if (answer.status === 200) return { kind: "material", body: answer.body };
			// A server failing, busy (429) or timed out (408) says nothing of the certificate.
			const down =
				(answer.status >= 500 && answer.status <= 599) ||
				answer.status === 429 ||
				answer.status === 408;
			return down ? { kind: "outage" } : { kind: "refused" };
		} catch (error) {
			if (DestinationRefused.is(error)) return { kind: "refused" };
			if (isUnavailable(error)) return { kind: "outage" };
			throw error;
		}
	};
	return { fetch, now: () => runtime.now(), random: (n) => runtime.random(n) };
}
