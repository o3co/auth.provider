import type { ExternalJwt } from "@mod/external-jwt";
import type { Clock, Log } from "@mod/kernel";
import { jsonObjectOf, type Outbound } from "@mod/outbound";
import {
	authorizationUrl,
	basicAuthorization,
	endSessionUrl,
	guarded,
	idTokenReaderOf,
	refreshAnswerOf,
	tokenAnswerOf,
} from "@mod/upstream-client";
import { type Upstream, UpstreamRefused } from "@mod/upstreams";
import type { Settings } from "./settings.ts";

/** Google's issuer, exactly as its id_tokens and callbacks must name it. */
export const issuer = "https://accounts.google.com";
const scopes = ["openid", "email", "profile"];

/** Google's OpenID Connect at fixed endpoints, without discovery. */
export function opened(
	s: Settings,
	outbound: Outbound,
	jwt: ExternalJwt,
	at: { readonly clock: Clock; readonly log: Log; readonly idp: string },
): Upstream {
	if (s["accept-missing-iss"]) at.log.warn("idp-google.iss_not_required", { idp: at.idp });
	const client = s["client-id"];
	const skewMs = s["clock-skew"] * 1000;
	const hostOf = (url: string) => new URL(url).hostname;
	const idTokenOf = idTokenReaderOf(
		jwt,
		{
			issuer,
			client,
			jwks: { url: s["jwks-uri"], hosts: [hostOf(s["jwks-uri"])] },
			algorithms: s.algorithms,
			skewMs,
			// Google names as azp another client of the same project that asked for the login.
			crossClient: true,
			emailVerified: [true],
			what: "idp-google",
		},
		at.clock,
	);
	const credential = basicAuthorization(client, s["client-secret"]);
	/** Posts to the token endpoint, the only host the client's secret goes to. */
	const post = (form: URLSearchParams) =>
		outbound.fetch(
			s["token-endpoint"],
			{
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					accept: "application/json",
				},
				body: form.toString(),
				credential,
			},
			{ hosts: [hostOf(s["token-endpoint"])] },
		);
	const offline = s.access === "offline";
	return {
		issuer,
		clockSkewMs: skewMs,
		authorizationUrl: (start) => {
			const prompt = [start.prompt, offline ? "consent" : undefined].filter(Boolean).join(" ");
			return authorizationUrl(
				s["authorization-endpoint"],
				start,
				{ clientId: client, scopes },
				{
					nonce: start.nonce,
					...(offline ? { access_type: "offline" } : {}),
					...(prompt ? { prompt } : {}),
					...(start.maxAgeSeconds === undefined ? {} : { max_age: String(start.maxAgeSeconds) }),
				},
			);
		},
		exchange: (exchange) =>
			guarded(async () => {
				// Mix-up: an answer from another issuer, or an empty iss, is refused before its code is used.
				if (exchange.iss !== undefined && exchange.iss !== issuer) throw new UpstreamRefused();
				// No iss only where the operator accepts its absence.
				if (exchange.iss === undefined && !s["accept-missing-iss"]) throw new UpstreamRefused();
				const answer = await post(
					new URLSearchParams({
						grant_type: "authorization_code",
						code: exchange.code,
						redirect_uri: exchange.redirectUri,
						code_verifier: exchange.verifier,
					}),
				);
				const { tokens, idToken } = tokenAnswerOf(jsonObjectOf(answer), scopes);
				if (!idToken) throw new UpstreamRefused();
				const { login, claims } = await idTokenOf(idToken, exchange.nonce, tokens.accessToken);
				// The domain is the checked id_token's own claim: never the authorize hint, nor the email's.
				const domains = s["hosted-domains"];
				if (domains && !(typeof claims.hd === "string" && domains.includes(claims.hd))) {
					throw new UpstreamRefused();
				}
				return { ...login, amr: [], tokens: { ...tokens, idToken } };
			}),
		refresh: (refreshToken, scopes) =>
			guarded(async () => {
				const form = new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
				});
				if (scopes.length > 0) form.set("scope", scopes.join(" "));
				return refreshAnswerOf(await post(form), scopes, "idp-google");
			}),
		endSession: (at) => {
			const configured = s["end-session-endpoint"];
			if (configured) return endSessionUrl(configured, at);
			// Google offers no end of session here: the browser only goes back, without the id_token.
			const back = at.postLogoutRedirectUri ?? `${issuer}/Logout`;
			return endSessionUrl(back, at.state === undefined ? {} : { state: at.state });
		},
	};
}
