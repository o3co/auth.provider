import { type Route, routes, use } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { amrSources, openedAfterHold } from "@mod/login-gates";
import { requestsPerSource } from "@mod/rate-limit";
import { handoff } from "@mod/upstream-handoff";
import { upstreams } from "@mod/upstreams";
import { upstreamNames } from "@mod/users";
import { amrSourceIn, idpsIn, upstreamNamesIn, upstreamsIn } from "./idps/idps.ts";
import { loginCaller, loginIn } from "./login/login.ts";
import { base, federationIdps, roundTripIn } from "./round-trip/round-trip.ts";
import { section } from "./section.ts";

/** The one handler both methods' routes share, built once. */
const federationRoute = contract<Pick<Route, "uses" | "handle">>("federation.route");

export default defineModule({ name: "federation", section }, (m) => [
	m.contribute(amrSources).by(amrSourceIn),
	m.provide(federationIdps).by(idpsIn),
	m.provide(upstreams).by(upstreamsIn),
	m.contribute(upstreamNames).by(upstreamNamesIn),
	// login-gates tells federation of a held login that opened; upstream-handoff keeps its tokens.
	m.contribute(openedAfterHold).by(async (c) => ({
		caller: loginCaller,
		opened: (await c.get(handoff)).opened,
	})),
	m.provide(federationRoute).by(async (c) => {
		const window = { limit: c.section.requests, ms: c.section.window * 1000 };
		const login = await loginIn(c);
		return {
			uses: [use(requestsPerSource, { name: "federation", window })],
			handle: await roundTripIn(c, { login }),
		};
	}),
	m.contribute(routes).by(async (c) => ({
		method: "GET",
		path: `${base}/*`,
		changesState: true,
		crossSite:
			"A start is the user's own navigation. A continuation's start checks what it asks before any transaction is made; a login's start takes a navigation from another site, its state bound to its cookie and taken once.",
		...(await c.get(federationRoute)),
	})),
	...(["GET", "POST"] as const).map((method) =>
		m.contribute(routes).by(async (c) => ({
			method,
			path: `${base}/*/callback`,
			...(method === "GET" ? { changesState: true } : {}),
			crossSite:
				"A callback is the IdP's redirect or form_post, from the IdP's own site. It takes a transaction only at that IdP, with the transaction's state, and only once.",
			...(await c.get(federationRoute)),
		})),
	),
]);
