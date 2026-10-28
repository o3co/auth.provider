import { claimsSelections } from "@mod/claims-selection";
import { type Route, routes } from "@mod/http";
import { endpointOrigin, issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule, isUnavailable } from "@mod/kernel";
import { releasedClaims } from "@mod/oidc";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { sessionTokens } from "@mod/session-tokens";
import { audienceAdditions, tokens } from "@mod/tokens";
import { type Settings, section } from "./section.ts";
import { unavailable, userinfoOver } from "./userinfo.ts";

const path = "/oauth/userinfo";

/** A page may send its token, its DPoP proof and a body's type, and read the challenge, the nonce and the wait. */
const cors = {
	headers: ["authorization", "dpop", "content-type"],
	exposes: ["www-authenticate", "dpop-nonce", "retry-after"],
};

/** The handler, answering a check or claims that cannot tell as `503`, never as a refusal. */
async function handlerOf(c: BuildContext<Settings>): Promise<Route["handle"]> {
	const userinfo = userinfoOver({
		now: c.clock.now,
		issuer: (await c.get(issuer)).url,
		requiresIssuer: c.section["issuer-audience"] === "on",
		senderBinding: await c.get(senderBinding),
		tokens: await c.get(tokens),
		sessionTokens: await c.get(sessionTokens),
		sessions: await c.get(sessions),
		selections: await c.get(claimsSelections),
		claims: await c.get(releasedClaims),
	});
	return async (request) => {
		try {
			return await userinfo(request);
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			// Answered here, so http never sees it: logged by what failed.
			c.log.warn("userinfo.unavailable", { what: error.what });
			return unavailable;
		}
	};
}

/** What its routes and its metadata take. */
const moduleTakes = [
	senderBinding,
	tokens,
	sessionTokens,
	sessions,
	claimsSelections,
	releasedClaims,
	issuer,
];

export default defineModule(
	{ name: "userinfo", section, replicaSafe: true, takes: moduleTakes },
	(m) => [
		...(["GET", "POST"] as const).map((method) =>
			m.contribute(routes).by(async (c) => ({
				method,
				path,
				cors,
				// A POST may carry a body, but the token is read from the header only.
				takes: ["form", "json", "none"],
				...(method === "GET"
					? { changesState: false }
					: {
							crossSite:
								"The access token comes in the Authorization header, never a cookie, and it only reads.",
							unlimited: "It is authenticated by a bearer access token and only reads.",
						}),
				handle: await handlerOf(c),
			})),
		),
		m.contribute(metadata).by(async (c) => {
			const origin = endpointOrigin(await c.get(issuer));
			return { name: "userinfo_endpoint", value: `${origin}${path}` };
		}),
		// A token issued for openid is for the issuer too, whose resource userinfo is (RFC 9700 §2.3).
		m.contribute(audienceAdditions).by(async (c) => {
			const { url } = await c.get(issuer);
			const mode = c.section["issuer-audience"];
			// Off or adding, userinfo takes a token not for it; said at start, so it is never left so unawares.
			if (mode !== "on") c.log.warn("userinfo.issuer_audience_not_required", { mode });
			return {
				name: "userinfo",
				added: (grant) => (mode !== "off" && grant.scope.includes("openid") ? [url] : []),
			};
		}),
	],
);
