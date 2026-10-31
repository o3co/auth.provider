import { claimsSelections } from "@mod/claims-selection";
import { type Route, routes } from "@mod/http";
import { endpointOrigin, issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { releasedClaims } from "@mod/oidc";
import { senderBinding } from "@mod/sender-binding";
import { sessions } from "@mod/session";
import { sessionTokens } from "@mod/session-tokens";
import { tokens } from "@mod/tokens";
import { unavailable, userinfoOver } from "./userinfo.ts";

const path = "/oauth/userinfo";

/** A page may send its token, its DPoP proof and a body's type, and read the challenge, the nonce and the wait. */
const cors = {
	headers: ["authorization", "dpop", "content-type"],
	exposes: ["www-authenticate", "dpop-nonce", "retry-after"],
};

/** The handler; a check or claims that cannot tell throw Unavailable, which the route answers. */
async function handlerOf(c: BuildContext<unknown>): Promise<Route["handle"]> {
	return userinfoOver({
		now: c.clock.now,
		senderBinding: await c.get(senderBinding),
		tokens: await c.get(tokens),
		sessionTokens: await c.get(sessionTokens),
		sessions: await c.get(sessions),
		selections: await c.get(claimsSelections),
		claims: await c.get(releasedClaims),
	});
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

export default defineModule({ name: "userinfo", replicaSafe: true, takes: moduleTakes }, (m) => [
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
			// `503`, never a refusal: http warns of it once, by what failed and the route.
			unavailable: { response: unavailable },
			handle: await handlerOf(c),
		})),
	),
	m.contribute(metadata).by(async (c) => {
		const origin = endpointOrigin(await c.get(issuer));
		return { name: "userinfo_endpoint", value: `${origin}${path}` };
	}),
]);
