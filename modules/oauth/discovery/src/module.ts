import { type Route, routes } from "@mod/http";
import { metadata, issuer as named } from "@mod/issuer";
import { defineModule } from "@mod/kernel";

const openid = "/.well-known/openid-configuration";
const oauth = "/.well-known/oauth-authorization-server";

/**
 * Where clients look for an issuer's document, with or without a trailing slash: OpenID Connect
 * Discovery appends its name to the issuer, RFC 8414 inserts its name before the issuer's path.
 * Without a path both are at the root; with one, the root would name another issuer.
 */
function pathsOf(issuer: string): readonly string[] {
	const path = new URL(issuer).pathname.replace(/\/$/, "");
	return [`${path}${openid}`, `${oauth}${path}`].flatMap((p) => [p, `${p}/`]);
}

export default defineModule({ name: "discovery" }, (m) =>
	// Every issuer has the same number of places, so each route is one of them.
	[0, 1, 2, 3].map((place) =>
		m.contribute(routes).by(async (c): Promise<Route> => {
			const issuer = (await c.get(named)).url;
			const items = (await c.collect(metadata)).filter((item) => item.value !== undefined);
			// The issuer comes first and is the configured one; request headers never shape the document.
			const document = {
				issuer,
				...Object.fromEntries(items.map((item) => [item.name, item.value])),
			};
			return {
				method: "GET",
				path: pathsOf(issuer)[place] as string,
				// Public metadata a page may read from any listed origin.
				cors: {},
				handle: () => ({ status: 200, headers: {}, body: { json: document } }),
			};
		}),
	),
);
