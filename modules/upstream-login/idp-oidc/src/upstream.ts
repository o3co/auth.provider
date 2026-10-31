import type { ExternalJwt } from "@mod/external-jwt";
import { withinHosts } from "@mod/host-entries";
import type { Clock, Log } from "@mod/kernel";
import {
	DestinationRefused,
	jsonObjectOf,
	type Outbound,
	type OutboundResponse,
} from "@mod/outbound";
import {
	browsedRefusalText,
	destinationRefusal,
	type OutboundRefusals,
} from "@mod/outbound-policy";
import {
	answerOf,
	authorizationUrl,
	basicAuthorization,
	endSessionUrl,
	guarded,
	idTokenReaderOf,
	refreshAnswerOf,
	tokenAnswerOf,
} from "@mod/upstream-client";
import {
	type AuthorizationStart,
	type DelegatedExchange,
	type Upstream,
	UpstreamMismatch,
	type UpstreamRefresh,
	UpstreamRefused,
	type UpstreamTokens,
} from "@mod/upstreams";
import { z } from "zod";
import { descriptionUrl, hostsOf, narrowerOf, type Settings, sentFor } from "./settings.ts";
import { describedUserinfoRefusal, userinfoOf } from "./userinfo/userinfo.ts";

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
/** The upstream's amr in its checked id_token, beyond what upstream-client reads. */
const amrClaim = z.looseObject({ amr: z.array(z.string()).optional() });

interface Endpoints {
	readonly authorization: string;
	readonly token: string;
	readonly jwks: string;
	readonly endSession?: string;
	/** Where UserInfo is read, where the operator turns its reading on. */
	readonly userinfo?: string;
}

/** How it reaches the upstream: outbound, and outbound's refusals of a destination at boot. */
interface Reach {
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

/** Opens an OpenID Connect upstream; throws, refusing boot, wherever its description does not hold. */
export async function opened(
	s: Settings,
	reach: Reach,
	jwt: ExternalJwt,
	at: { readonly clock: Clock; readonly log: Log; readonly idp: string },
): Promise<Upstream> {
	const { outbound } = reach;
	const hosts = hostsOf(s);
	const from = sentFor(s);
	const { endpoints, offersIss } = s.discovery
		? await discovered(s, reach, hosts)
		: { endpoints: given(s), offersIss: false };
	const requireIss = !s["accept-missing-iss"] || offersIss;
	if (!requireIss) at.log.warn("idp-oidc.iss_not_required", { idp: at.idp });
	const skewMs = s["clock-skew"] * 1000;
	const client = s["client-id"];
	const idTokenOf = idTokenReaderOf(
		jwt,
		{
			issuer: s.issuer,
			client,
			jwks: { url: endpoints.jwks, ...narrowerOf(hosts, from.jwks) },
			algorithms: s.algorithms,
			skewMs,
			emailVerified: [true],
			what: "idp-oidc",
		},
		at.clock,
	);
	/**
	 * The upstream login an id_token says, once it holds for this client, login and access token;
	 * its profile completed by UserInfo where `userinfo` names it, the id_token checked first.
	 */
	const upstreamLoginOf = async (
		idToken: string,
		nonce: string,
		tokens: UpstreamTokens,
		userinfo: string | undefined,
	) => {
		const checked = await idTokenOf(idToken, nonce, tokens.accessToken);
		const read = amrClaim.safeParse(checked.claims);
		if (!read.success) throw new UpstreamRefused();
		const login =
			userinfo === undefined
				? checked.login
				: checked.withUserinfo(
						await userinfoOf(outbound, userinfo, tokens, narrowerOf(hosts, from.userinfo)),
					);
		return { ...login, amr: read.data.amr ?? [] };
	};
	const post = s["token-auth"] === "client_secret_post";
	/** Posts a grant to the token endpoint, with the client's secret as the operator says. */
	const granting = (grant: Readonly<Record<string, string>>): Promise<OutboundResponse> => {
		const form = new URLSearchParams({
			...grant,
			...(post ? { client_id: client, client_secret: s["client-secret"] } : {}),
		});
		const headers = {
			"content-type": "application/x-www-form-urlencoded",
			accept: "application/json",
		};
		const sent = post ? {} : { credential: basicAuthorization(client, s["client-secret"]) };
		return outbound.fetch(
			endpoints.token,
			{ method: "POST", headers, body: form.toString(), ...sent },
			narrowerOf(hosts, from.token),
		);
	};
	/**
	 * The login and the tokens of a code; its scopes are what an answer without a scope stands for.
	 * UserInfo is read where `userinfo` names it: a login's code, never a delegation's.
	 */
	const exchanged = (code: DelegatedExchange, userinfo?: string) =>
		guarded(async () => {
			// Mix-up: an answer from another issuer is refused before its code is used.
			if (code.iss === undefined ? requireIss : code.iss !== s.issuer) {
				throw new UpstreamRefused();
			}
			const answer = await granting({
				grant_type: "authorization_code",
				code: code.code,
				redirect_uri: code.redirectUri,
				code_verifier: code.verifier,
				...(code.resource === undefined ? {} : { resource: code.resource }),
			});
			const { tokens, idToken } = tokenAnswerOf(jsonObjectOf(answer), code.scopes);
			if (!idToken) throw new UpstreamRefused();
			const login = await upstreamLoginOf(idToken, code.nonce, tokens, userinfo);
			return { ...login, tokens: { ...tokens, idToken } };
		});
	const refreshed = (refreshToken: string, scopes: readonly string[], resource?: string) =>
		guarded(async (): Promise<UpstreamRefresh> => {
			const answer = await granting({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				...(scopes.length > 0 ? { scope: scopes.join(" ") } : {}),
				...(resource === undefined ? {} : { resource }),
			});
			return refreshAnswerOf(answer, scopes, "idp-oidc");
		});
	/** A start's own parameters: the nonce, and the browser's prompt and max age. */
	const asking = (start: AuthorizationStart, prompt: string | undefined) => ({
		nonce: start.nonce,
		...(prompt ? { prompt } : {}),
		...(start.maxAgeSeconds === undefined ? {} : { max_age: String(start.maxAgeSeconds) }),
	});
	const { endSession } = endpoints;
	return {
		issuer: s.issuer,
		clockSkewMs: skewMs,
		authorizationUrl: (start) =>
			authorizationUrl(
				endpoints.authorization,
				start,
				{ clientId: client, scopes: s.scopes },
				asking(start, start.prompt),
			),
		exchange: (code) => exchanged({ ...code, scopes: s.scopes }, endpoints.userinfo),
		// The login's refresh passes no resource.
		refresh: (refreshToken, scopes) => refreshed(refreshToken, scopes),
		delegation: {
			authorizationUrl: (start) => {
				if (!start.scopes.includes("openid")) return { kind: "refused" };
				// Offline access is granted only where the user is asked (OpenID Connect Core §11).
				const consent = start.scopes.includes("offline_access") ? "consent" : undefined;
				const prompt = [start.prompt, consent].filter(Boolean).join(" ");
				return authorizationUrl(
					endpoints.authorization,
					start,
					{ clientId: client, scopes: start.scopes },
					{
						...asking(start, prompt),
						...(start.resource === undefined ? {} : { resource: start.resource }),
					},
				);
			},
			exchange: async (code: DelegatedExchange) => ({
				...(await exchanged(code)),
				issuer: s.issuer,
			}),
			refresh: refreshed,
		},
		...(endSession === undefined
			? {}
			: {
					endSession: (at) => endSessionUrl(endSession, { ...at, clientId: client }),
				}),
	};
}
