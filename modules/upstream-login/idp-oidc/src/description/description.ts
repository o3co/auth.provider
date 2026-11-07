import { withinHosts } from "@mod/host-entries";
import { DestinationRefused, jsonObjectOf, type Outbound } from "@mod/outbound";
import {
	browsedRefusalText,
	destinationRefusal,
	type OutboundRefusals,
} from "@mod/outbound-policy";
import { answerOf } from "@mod/upstream-client";
import { UpstreamMismatch } from "@mod/upstreams";
import { z } from "zod";
import { descriptionUrl, narrowerOf, type Settings } from "../settings.ts";
import { describedUserinfoRefusal } from "../userinfo/userinfo.ts";

const description = z.looseObject({
	issuer: z.string(),
	authorization_endpoint: z.url(),
	token_endpoint: z.url(),
	jwks_uri: z.url(),
	end_session_endpoint: z.url().optional(),
	// Read only where the operator reads UserInfo: what a description says of it is no matter otherwise.
	userinfo_endpoint: z.unknown().optional(),
	authorization_response_iss_parameter_supported: z.boolean().optional(),
});

export interface Endpoints {
	readonly authorization: string;
	readonly token: string;
	readonly jwks: string;
	readonly endSession?: string;
	/** Where UserInfo is read, where the operator turns its reading on. */
	readonly userinfo?: string;
}

/** How it reaches the upstream: outbound, and outbound's refusals of a destination at boot. */
export interface Reach {
	readonly outbound: Outbound;
	readonly refusals: OutboundRefusals;
}

/** A description that does not hold, told under `issuer`: the key it was read from. */
const mismatch = (reason: string) => new UpstreamMismatch(reason, ["issuer"]);

/** The endpoints the issuer's description names; throws, refusing boot, where they do not hold. */
async function discovered(s: Settings, { outbound, refusals }: Reach, hosts: readonly string[]) {
	const where = descriptionUrl(s.issuer);
	// A destination outbound refuses, as an answer that does not hold, refuses boot under the issuer.
	const fetched = await outbound
		.fetch(where, {}, narrowerOf(hosts, s.issuer))
		.catch((error: unknown) => {
			if (!DestinationRefused.is(error)) throw error;
			throw mismatch(`outbound's destination policy refuses the description: ${error.reason}`);
		});
	// Refused as the upstream's answer, which at boot refuses boot.
	const described = answerOf(jsonObjectOf(fetched), description);
	if (described.issuer !== s.issuer) throw mismatch("the description names another issuer");
	const endSession = described.end_session_endpoint;
	// The end of session too: the browser takes the login's id_token there.
	const all = [
		described.authorization_endpoint,
		described.token_endpoint,
		described.jwks_uri,
		...(endSession ? [endSession] : []),
	];
	if (all.some((url) => !withinHosts(url, hosts))) {
		throw mismatch("the description names an endpoint on a host the operator did not name");
	}
	// The browser goes to these, which outbound never reaches: its policy for them decides.
	const browsed = {
		authorization_endpoint: described.authorization_endpoint,
		...(endSession ? { end_session_endpoint: endSession } : {}),
	};
	for (const [name, url] of Object.entries(browsed)) {
		const narrowed = narrowerOf(hosts, s.issuer);
		const refused = browsedRefusalText(refusals, url, narrowed, `the description's ${name}`);
		if (refused !== undefined) throw mismatch(refused);
	}
	// The two this server sends to; a refusal here would fail every login.
	const sent = { token_endpoint: described.token_endpoint, jwks_uri: described.jwks_uri };
	for (const [name, url] of Object.entries(sent)) {
		const narrowed = narrowerOf(hosts, s.issuer);
		const refused = destinationRefusal(refusals, url, narrowed, `the description's ${name}`);
		if (refused !== undefined) throw mismatch(refused);
	}
	// UserInfo only where the operator reads it: a description naming it is no matter otherwise.
	const named = described.userinfo_endpoint;
	const userinfo =
		s["read-userinfo"] && typeof named === "string" && URL.canParse(named) ? named : undefined;
	if (s["read-userinfo"]) {
		const narrowed = narrowerOf(hosts, s.issuer);
		const refused = describedUserinfoRefusal(userinfo, hosts, narrowed, refusals);
		if (refused !== undefined) throw mismatch(refused);
	}
	const endpoints: Endpoints = {
		authorization: described.authorization_endpoint,
		token: described.token_endpoint,
		jwks: described.jwks_uri,
		...(endSession ? { endSession } : {}),
		...(userinfo ? { userinfo } : {}),
	};
	return {
		endpoints,
		offersIss: described.authorization_response_iss_parameter_supported === true,
	};
}

/** The endpoints the operator gives without discovery (its settings hold all three then). */
const given = (s: Settings): Endpoints => ({
	authorization: s["authorization-endpoint"] ?? "",
	token: s["token-endpoint"] ?? "",
	jwks: s["jwks-uri"] ?? "",
	...(s["end-session-endpoint"] ? { endSession: s["end-session-endpoint"] } : {}),
	...(s["read-userinfo"] && s["userinfo-endpoint"] ? { userinfo: s["userinfo-endpoint"] } : {}),
});

/**
 * The upstream's endpoints, and whether its description offers `iss`: read from the issuer's
 * description with discovery, else as the operator gives them. Throws, refusing boot, where the
 * description does not hold.
 */
export async function describedBy(
	s: Settings,
	reach: Reach,
	hosts: readonly string[],
): Promise<{ readonly endpoints: Endpoints; readonly offersIss: boolean }> {
	return s.discovery ? discovered(s, reach, hosts) : { endpoints: given(s), offersIss: false };
}
