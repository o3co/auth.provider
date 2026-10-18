import { createPrivateKey } from "node:crypto";
import type { ExternalJwt } from "@mod/external-jwt";
import type { Clock } from "@mod/kernel";
import { jsonObjectOf, type Outbound } from "@mod/outbound";
import {
	authorizationUrl,
	endSessionUrl,
	guarded,
	idTokenReaderOf,
	refreshAnswerOf,
	tokenAnswerOf,
} from "@mod/upstream-client";
import { type Upstream, UpstreamRefused } from "@mod/upstreams";
import { secretOf } from "./client-secret/secret.ts";
import type { Settings } from "./settings.ts";

/** Apple's issuer, exactly as its id_tokens and any callback `iss` must name it. */
export const issuer = "https://appleid.apple.com";

const loopback = (host: string) =>
	host === "localhost" || host === "localhost." || host === "[::1]" || /^127(\.\d+){3}$/.test(host);

/** The secret to send: the fixed one, or one the team's key signs. Throws, naming no value, on a key that is no P-256 key in PKCS8. */
function secretFrom(s: Settings, clock: Clock): () => Promise<string> {
	const { "client-secret": fixed, "team-id": teamId, "key-id": keyId, "private-key": pem } = s;
	if (fixed !== undefined) return async () => fixed;
	if (!teamId || !keyId || !pem) throw new Error("no client secret");
	const key = (() => {
		try {
			return createPrivateKey({ key: pem, format: "pem" });
		} catch {
			throw new Error("the private key cannot be read");
		}
	})();
	const curve = key.asymmetricKeyDetails?.namedCurve;
	if (!pem.includes("-----BEGIN PRIVATE KEY-----") || curve !== "prime256v1") {
		throw new Error("the private key is no P-256 key in PKCS8");
	}
	const lifetimeMs = s["secret-lifetime"] * 1000;
	const held = secretOf(
		{ teamId, keyId, clientId: s["client-id"], key, lifetimeMs, audience: issuer },
		clock,
	);
	return () => held.current();
}

/** Sign in with Apple; refuses boot for a callback Apple would refuse, or a key it cannot sign with. */
export function opened(
	s: Settings,
	outbound: Outbound,
	jwt: ExternalJwt,
	at: { readonly clock: Clock; readonly redirectUri: string },
): Upstream {
	const callback = new URL(at.redirectUri);
	if (callback.protocol !== "https:" || loopback(callback.hostname)) {
		throw new Error("Apple takes only an https callback off loopback");
	}
	const secret = secretFrom(s, at.clock);
	const client = s["client-id"];
	const skewMs = s["clock-skew"] * 1000;
	const hostOf = (url: string) => new URL(url).hostname;
	const idTokenOf = idTokenReaderOf(
		jwt,
		{
			issuer,
			client,
			jwks: { url: s["jwks-uri"], hosts: [hostOf(s["jwks-uri"])] },
			algorithms: ["RS256"],
			skewMs,
			// Apple has sent `email_verified` both as a boolean and as text.
			emailVerified: [true, "true"],
			what: "idp-apple",
		},
		at.clock,
	);
	/** Posts to the token endpoint with the client's secret in the form, the only host it goes to. */
	const post = async (fields: Record<string, string>) =>
		outbound.fetch(
			s["token-endpoint"],
			{
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					accept: "application/json",
				},
				body: new URLSearchParams({
					...fields,
					client_id: client,
					client_secret: await secret(),
				}).toString(),
			},
			{ hosts: [hostOf(s["token-endpoint"])] },
		);
	const end = s["end-session-endpoint"];
	return {
		issuer,
		responseMode: "form_post",
		clockSkewMs: skewMs,
		// Apple takes no freshness, so a browser's prompt and max age are not sent.
		authorizationUrl: (start) =>
			authorizationUrl(
				s["authorization-endpoint"],
				{ ...start, redirectUri: at.redirectUri },
				{ clientId: client, scopes: s.scopes },
				{ response_mode: "form_post", nonce: start.nonce },
			),
		exchange: (exchange) =>
			guarded(async () => {
				// Apple sends no `iss`; one that names another issuer is refused before its code is used.
				if (exchange.iss !== undefined && exchange.iss !== issuer) throw new UpstreamRefused();
				const answer = await post({
					grant_type: "authorization_code",
					code: exchange.code,
					redirect_uri: at.redirectUri,
					code_verifier: exchange.verifier,
				});
				const { tokens, idToken } = tokenAnswerOf(jsonObjectOf(answer), s.scopes);
				if (!idToken) throw new UpstreamRefused();
				const { login } = await idTokenOf(idToken, exchange.nonce, tokens.accessToken);
				return { ...login, amr: [], tokens: { ...tokens, idToken } };
			}),
		refresh: (refreshToken, scopes) =>
			guarded(async () => {
				const answer = await post({ grant_type: "refresh_token", refresh_token: refreshToken });
				return refreshAnswerOf(answer, scopes, "idp-apple");
			}),
		...(end ? { endSession: (ending) => endSessionUrl(end, ending) } : {}),
	};
}
