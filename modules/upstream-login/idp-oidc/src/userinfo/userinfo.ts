import { Unavailable } from "@mod/kernel";
import type { Narrower, Outbound, OutboundResponse } from "@mod/outbound";
import { destinationRefusal, type OutboundRefusals, withinHosts } from "@mod/outbound-policy";
import { UpstreamRefused, type UpstreamTokens } from "@mod/upstreams";

/**
 * Why the description's UserInfo endpoint cannot be read from, where the operator reads it: none
 * named, one on a host the operator did not name, one not on https, or one outbound's policy refuses.
 */
export function describedUserinfoRefusal(
	url: string | undefined,
	hosts: readonly string[],
	narrowed: Narrower,
	refusals: OutboundRefusals,
): string | undefined {
	if (url === undefined) return "the description names no userinfo_endpoint";
	if (!withinHosts(url, hosts)) {
		return "the description's userinfo_endpoint is on a host the operator did not name";
	}
	if (new URL(url).protocol !== "https:") {
		return "the description's userinfo_endpoint is not https, which read-userinfo needs";
	}
	return destinationRefusal(refusals, url, narrowed, "the description's userinfo_endpoint");
}

/**
 * UserInfo's answer for a login's tokens: its access token sent by `GET` as the Bearer credential
 * to `at` alone. A token that is no Bearer token refuses; a 5xx is the upstream unavailable, told
 * before the answer is read.
 */
export async function userinfoOf(
	outbound: Outbound,
	at: string,
	tokens: UpstreamTokens,
	narrowed: Narrower,
): Promise<OutboundResponse> {
	if (tokens.tokenType.toLowerCase() !== "bearer") throw new UpstreamRefused();
	const answer = await outbound.fetch(
		at,
		{
			method: "GET",
			headers: { accept: "application/json" },
			credential: `Bearer ${tokens.accessToken}`,
		},
		narrowed,
	);
	if (answer.status >= 500) throw new Unavailable("idp-oidc");
	return answer;
}
