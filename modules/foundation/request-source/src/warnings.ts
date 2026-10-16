import type { Clock } from "@mod/kernel";
import type { TrustedProxies } from "./settings.ts";
import { canonical, trusts } from "./source.ts";

const minute = 60_000;

/** Whether to warn now of `X-Forwarded-For` from a peer not trusted: at most once a minute. */
export function ignoredForwarding(proxies: TrustedProxies, clock: Clock) {
	let last = Number.NEGATIVE_INFINITY;
	return (peer: string, headers: ReadonlyMap<string, string>) => {
		if (!headers.has("x-forwarded-for") || trusts(proxies, canonical(peer) ?? peer)) return false;
		const now = clock.now();
		if (now - last <= minute) return false;
		last = now;
		return true;
	};
}
