import type { ExternalJwt } from "@mod/external-jwt";
import type { Clock, Log } from "@mod/kernel";
import {
	jsonObjectOf,
	type Outbound,
	type OutboundPolicy,
	type OutboundResponse,
	withinHosts,
} from "@mod/outbound";
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
	type UpstreamRefresh,
	UpstreamRefused,
} from "@mod/upstreams";
import { z } from "zod";
import { descriptionUrl, hostsOf, type Settings } from "./settings.ts";

const description = z.looseObject({
	issuer: z.string(),
	authorization_endpoint: z.url(),
	token_endpoint: z.url(),
	jwks_uri: z.url(),
	end_session_endpoint: z.url().optional(),
	authorization_response_iss_parameter_supported: z.boolean().optional(),
});
/** The upstream's amr in its checked id_token, beyond what upstream-client reads. */
const amrClaim = z.looseObject({ amr: z.array(z.string()).optional() });

interface Endpoints {
	readonly authorization: string;
	readonly token: string;
	readonly jwks: string;
	readonly endSession?: string;
}

/** How it reaches the upstream: outbound, and outbound's destination policy at boot. */
interface Reach {
	readonly outbound: Outbound;
	readonly policy: OutboundPolicy;
}

/** The endpoints the issuer's description names; throws, refusing boot, where they do not hold. */
async function discovered(s: Settings, { outbound, policy }: Reach, hosts: readonly string[]) {
	const where = descriptionUrl(s.issuer);
	// Refused as the upstream's answer, which at boot refuses boot.
	const described = answerOf(jsonObjectOf(await outbound.fetch(where, {}, { hosts })), description);
	if (described.issuer !== s.issuer) throw new Error("the description names another issuer");
	const endSession = described.end_session_endpoint;
	// The end of session too: the browser takes the login's id_token there.
	const all = [
		described.authorization_endpoint,
		described.token_endpoint,
		described.jwks_uri,
		...(endSession ? [endSession] : []),
	];
	if (all.some((url) => !withinHosts(url, hosts))) {
		throw new Error("the description names an endpoint on a host the operator did not name");
	}
	// The browser goes to some of them: https, or plain http where the operator named the issuer so.
	const schemes = ["https:", new URL(s.issuer).protocol];
	if (all.some((url) => !schemes.includes(new URL(url).protocol))) {
		throw new Error("the description names an endpoint that is not https");
	}
	// The two this server sends to; a refusal here would fail every login.
	const sent = [described.token_endpoint, described.jwks_uri];
	if (sent.some((url) => policy.refusalOf(url, { hosts }) !== undefined)) {
		throw new Error("outbound's destination policy refuses an endpoint the description names");
	}
	const endpoints: Endpoints = {
		authorization: described.authorization_endpoint,
		token: described.token_endpoint,
		jwks: described.jwks_uri,
		...(endSession ? { endSession } : {}),
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
});

/** Opens an OpenID Connect upstream; throws, refusing boot, wherever its description does not hold. */
export async function opened(
	s: Settings,
	reach: Reach,
	jwt: ExternalJwt,
	at: { readonly clock: Clock; readonly log: Log; readonly name: string },
): Promise<Upstream> {
	const { outbound } = reach;
	const hosts = hostsOf(s);
	const { endpoints, offersIss } = s.discovery
		? await discovered(s, reach, hosts)
		: { endpoints: given(s), offersIss: false };
	const requireIss = s["require-iss"] || offersIss;
	if (!requireIss) at.log.warn("idp-oidc.iss_not_required", { idp: at.name });
	const skewMs = s["clock-skew-seconds"] * 1000;
	const client = s["client-id"];
	const idTokenOf = idTokenReaderOf(
		jwt,
		{
			issuer: s.issuer,
			client,
			jwks: { url: endpoints.jwks, hosts },
			algorithms: s.algorithms,
			skewMs,
			emailVerified: [true],
			what: "idp-oidc",
		},
		at.clock,
	);
	/** The upstream login an id_token says, once it holds for this client and login. */
	const upstreamLoginOf = async (idToken: string, nonce: string) => {
		const { login, claims } = await idTokenOf(idToken, nonce);
		const read = amrClaim.safeParse(claims);
		if (!read.success) throw new UpstreamRefused();
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
			...(post ? {} : { authorization: basicAuthorization(client, s["client-secret"]) }),
		};
		return outbound.fetch(
			endpoints.token,
			{ method: "POST", headers, body: form.toString() },
			{ hosts },
		);
	};
	/** The login and the tokens of a code; its scopes are what an answer without a scope stands for. */
	const exchanged = (code: DelegatedExchange) =>
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
			const login = await upstreamLoginOf(idToken, code.nonce);
			return { ...login, tokens: { ...tokens, idToken } };
		});
	const refreshed = (refreshToken: string, scope: readonly string[], resource?: string) =>
		guarded(async (): Promise<UpstreamRefresh> => {
			const answer = await granting({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				...(scope.length > 0 ? { scope: scope.join(" ") } : {}),
				...(resource === undefined ? {} : { resource }),
			});
			return refreshAnswerOf(answer, scope, "idp-oidc");
		});
	/** A start's own parameters: the nonce, and the browser's prompt and max age. */
	const asking = (start: AuthorizationStart, prompt: string | undefined) => ({
		nonce: start.nonce,
		...(prompt ? { prompt } : {}),
		...(start.maxAgeSeconds === undefined ? {} : { max_age: String(start.maxAgeSeconds) }),
	});
	const { endSession } = endpoints;
	return {
		clockSkewMs: skewMs,
		authorizationUrl: (start) =>
			authorizationUrl(
				endpoints.authorization,
				start,
				{ clientId: client, scopes: s.scopes },
				asking(start, start.prompt),
			),
		exchange: (code) => exchanged({ ...code, scopes: s.scopes }),
		// The login's refresh passes no resource.
		refresh: (refreshToken, scope) => refreshed(refreshToken, scope),
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
