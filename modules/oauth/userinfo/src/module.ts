import { type Route, routes, site } from "@mod/http";
import { metadata } from "@mod/issuer";
import { type BuildContext, defineModule, isUnavailable } from "@mod/kernel";
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

/** The handler, answering a check or claims that cannot tell as `503`, never as a refusal. */
async function handlerOf(c: BuildContext<unknown>): Promise<Route["handle"]> {
	const userinfo = userinfoOver({
		senderBinding: await c.get(senderBinding),
		tokens: await c.get(tokens),
		sessionTokens: await c.get(sessionTokens),
		sessions: await c.get(sessions),
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
const moduleTakes = [senderBinding, tokens, sessionTokens, sessions, releasedClaims, site];

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
			handle: await handlerOf(c),
		})),
	),
	m.contribute(metadata).by(async (c) => {
		const origin = (await c.get(site)).origin;
		return { name: "userinfo_endpoint", value: origin && `${origin}${path}` };
	}),
]);
