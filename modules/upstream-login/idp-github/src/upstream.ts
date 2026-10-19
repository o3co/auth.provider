import { jsonObjectOf, type Outbound, type OutboundRequest } from "@mod/outbound";
import { answerOf, authorizationUrl, guarded } from "@mod/upstream-client";
import { type Upstream, UpstreamRefused } from "@mod/upstreams";
import { z } from "zod";
import { hostsOf, type Settings, userUrl } from "./settings.ts";

const tokenAnswer = z.looseObject({
	access_token: z.string().min(1),
	token_type: z.string().regex(/^bearer$/i),
});
/** GitHub's numeric id: a JSON number within the safe integers, or its canonical digits. */
const id = z.union([
	// zod's int() takes only safe integers.
	z.number().int().positive(),
	z
		.string()
		.regex(/^[1-9][0-9]{0,15}$/)
		.refine((digits) => Number.isSafeInteger(Number(digits))),
]);
const user = z.looseObject({ id });

/**
 * The public profile in GitHub's user answer: text kept as text. The answer cannot say the email
 * is verified (GitHub says so only in its list of emails), so it never is.
 */
function profileOf(said: Readonly<Record<string, unknown>>) {
	const { email, name, avatar_url: picture } = said;
	const profile = {
		...(typeof email === "string" ? { email, emailVerified: false } : {}),
		...(typeof name === "string" ? { name } : {}),
		...(typeof picture === "string" ? { picture } : {}),
	};
	return Object.keys(profile).length > 0 ? { profile } : {};
}

/** GitHub's OAuth (not OpenID Connect): the subject is the user's numeric id, read from its API. */
export function opened(s: Settings, outbound: Outbound): Upstream {
	const hosts = hostsOf(s);
	return {
		issuer: s.issuer,
		authorizationUrl: (start) =>
			authorizationUrl(s["authorization-endpoint"], start, {
				clientId: s["client-id"],
				scopes: s.scopes,
			}),
		exchange: async (exchange) => {
			if (exchange.iss !== undefined && exchange.iss !== s.issuer) throw new UpstreamRefused();
			const form = new URLSearchParams({
				grant_type: "authorization_code",
				code: exchange.code,
				redirect_uri: exchange.redirectUri,
				code_verifier: exchange.verifier,
				client_id: s["client-id"],
				client_secret: s["client-secret"],
			});
			const tokenRequest: OutboundRequest = {
				method: "POST",
				headers: {
					"content-type": "application/x-www-form-urlencoded",
					accept: "application/json",
				},
				body: form.toString(),
			};
			return guarded(async () => {
				const granted = await outbound.fetch(s["token-endpoint"], tokenRequest, { hosts });
				// GitHub answers a refused code with 200 and an error, so the token itself is required.
				const { access_token } = answerOf(jsonObjectOf(granted), tokenAnswer);
				const userRequest: OutboundRequest = {
					headers: { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" },
					credential: `Bearer ${access_token}`,
				};
				const found = await outbound.fetch(userUrl(s.api), userRequest, { hosts });
				const read = answerOf(jsonObjectOf(found), user);
				return { subject: String(read.id), amr: [], ...profileOf(read) };
			});
		},
	};
}
