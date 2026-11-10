import { DestinationRefused, type Policy } from "@mod/outbound-policy";
import { isOutboundUnavailable } from "../contract.ts";
import type { Fetched } from "../revocation/revocation.ts";
import type { Tls } from "../tls/tls.ts";
import { type Resolver, type Route, send } from "../transport/transport.ts";

/** A server failing (5xx), busy (429) or timed out (408): it may answer later. */
const mayAnswerLater = (status: number) =>
	(status >= 500 && status <= 599) || status === 429 || status === 408;

/**
 * How a CRL is fetched for a peer's check: as signed material, plain http at `hosts` and public
 * addresses alone, 1 MiB and 5 seconds at most, in the place of the request it is for, never around
 * the proxy (until a CRL goes through it, one the proxy would carry is unreachable); `aborted` where
 * the request's own signal ended it.
 */
export function crlFetchOf(
	hosts: readonly string[],
	policy: Policy,
	route: Route | undefined,
	resolve: Resolver,
	tls: Tls,
	deadlineOf: (ms: number) => AbortSignal,
) {
	const narrower = { hosts, outsideChosen: true as const, maxBytes: 1 << 20, timeoutMs: 5000 };
	return async (url: string, signal: AbortSignal): Promise<Fetched> => {
		if (signal.aborted) return "aborted";
		try {
			const admitted = policy.admit(url, narrower, true);
			if (route !== undefined && !route.direct(admitted.host)) return "unreachable";
			const answer = await send(
				admitted,
				{ method: "GET" },
				policy.limitsOf(narrower, true),
				resolve,
				policy,
				route,
				tls,
				(ms) => AbortSignal.any([signal, deadlineOf(ms)]),
			);
			if (answer.status === 200) return answer.body;
			return mayAnswerLater(answer.status) ? "unreachable" : "refused";
		} catch (error) {
			if (signal.aborted) return "aborted";
			if (DestinationRefused.is(error)) return "refused";
			if (!isOutboundUnavailable(error)) throw error;
			return error.failure === "too-large" ? "too-large" : "unreachable";
		}
	};
}
