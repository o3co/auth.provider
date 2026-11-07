import type { ExternalJwt } from "@mod/external-jwt";
import type { Clock, Log } from "@mod/kernel";
import { jsonObjectOf } from "@mod/outbound";
import {
	authorizationUrl,
	endSessionUrl,
	guarded,
	idTokenReaderOf,
	refreshAnswerOf,
	tokenAnswerOf,
	tokenPostOf,
} from "@mod/upstream-client";
import {
	type AuthorizationStart,
	type DelegatedExchange,
	type Upstream,
	type UpstreamRefresh,
	UpstreamRefused,
	type UpstreamTokens,
} from "@mod/upstreams";
import { z } from "zod";
import { describedBy, type Reach } from "./description/description.ts";
import { hostsOf, narrowerOf, type Settings, sentFor } from "./settings.ts";
import { userinfoOf } from "./userinfo/userinfo.ts";

/** The upstream's amr in its checked id_token, beyond what upstream-client reads. */
const amrClaim = z.looseObject({ amr: z.array(z.string()).optional() });

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
	const { endpoints, offersIss } = await describedBy(s, reach, hosts);
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
	/** Posts a grant to the token endpoint, with the client's secret as the operator says. */
	const granting = tokenPostOf(
		outbound,
		endpoints.token,
		{
			id: client,
			auth: s["token-auth"] === "client_secret_post" ? "form" : "basic",
			secret: async () => s["client-secret"],
		},
		narrowerOf(hosts, from.token),
	);
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
