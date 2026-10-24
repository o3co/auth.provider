import { routes } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { amrSources, loginGates } from "@mod/login-gates";
import { amrOf } from "./facts/facts.ts";
import { gateIn, gateTakes } from "./gate/gate.ts";
import { routesIn, routesTakes } from "./routes/routes.ts";
import { section } from "./section.ts";

/** What the module takes: its helpers' (`routesIn`, `gateIn`); its amr source takes nothing. */
const takes = [...routesTakes, ...gateTakes];

export default defineModule({ name: "login-passkey", section, takes }, (m) => [
	m.contribute(amrSources).by((c) => ({
		name: "login-passkey",
		amr: amrOf(true, c.section["counts-as-mfa"]),
	})),
	// The options route, then the login route.
	...[0, 1].map((at) =>
		m.contribute(routes).by(async (c) => {
			const made = await routesIn(c);
			return made[at] as (typeof made)[number];
		}),
	),
	m.contribute(loginGates).by(gateIn),
]);
