import { type Route, routes, use } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { amrSources, openedAfterHold } from "@mod/login-gates";
import { requestsPerSource } from "@mod/rate-limit";
import { upstreams } from "@mod/upstreams";
import { handoff, handoffIn, openedIn } from "./handoff/handoff.ts";
import { amrSourceIn, idpsIn, upstreamsIn } from "./idps/idps.ts";
import { linkIn } from "./link/link.ts";
import { loginIn } from "./round-trip/login.ts";
import { base, federationIdps, roundTripIn } from "./round-trip/round-trip.ts";
import { section } from "./section.ts";

/** The one handler both methods' routes share, built once. */
const federationRoute = contract<Pick<Route, "uses" | "handle">>("federation.route");

export default defineModule({ name: "federation", section }, (m) => [
	m.contribute(amrSources).by(amrSourceIn),
	m.provide(federationIdps).by(idpsIn),
	m.provide(upstreams).by(upstreamsIn),
	m.provide(handoff).by(handoffIn),
	m.contribute(openedAfterHold).by(openedIn),
	m.provide(federationRoute).by(async (c) => {
		const window = { limit: c.section.requests, ms: c.section["window-seconds"] * 1000 };
		const login = await loginIn(c);
		const link = await linkIn(c);
		return {
			uses: [use(requestsPerSource, { name: "federation", window })],
			handle: await roundTripIn(c, { login, link }),
		};
	}),
	...(["GET", "POST"] as const).map((method) =>
		m.contribute(routes).by(async (c) => ({
			method,
			path: `${base}/*`,
			...(await c.get(federationRoute)),
		})),
	),
]);
