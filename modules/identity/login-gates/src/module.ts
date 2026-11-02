import { site } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { sessions } from "@mod/session";
import { loopbackPagesRefused, urlSetting } from "@mod/url-setting";
import { z } from "zod";
import { amrSources, loginGates, logins, openedAfterHold, returnPaths } from "./contract.ts";
import { returnsWith } from "./returns/returns.ts";
import { runningWith } from "./running/running.ts";

const section = z.strictObject({
	"return-targets": z
		.array(urlSetting({ schemes: ["https"], loopbackHttp: true }))
		.prefault([])
		.describe(
			"The https URLs (http only on a loopback host, with `kernel.environment = development`), matched as written, a login may return to besides the return paths modules contribute.",
		),
});

export default defineModule(
	{
		name: "login-gates",
		refusedInProduction: (s) => loopbackPagesRefused({ "return-targets": s["return-targets"] }),
		section,
		replicaSafe: true,
		takes: [site, amrSources, loginGates, openedAfterHold, returnPaths, sessions],
	},
	(m) => [
		m.provide(logins).by(async (c) => {
			// By name in code units, not locale, so every host runs them alike. Names are keyed, never equal.
			const gates = (await c.collect(loginGates)).toSorted((a, b) => (a.name < b.name ? -1 : 1));
			const provable = new Set((await c.collect(amrSources)).flatMap((source) => source.amr));
			const { returnAllowed } = returnsWith({
				targets: c.section["return-targets"],
				origin: (await c.get(site)).origin,
				contributed: await c.collect(returnPaths),
				refuse: c.refuse,
			});
			const callers = new Map(
				(await c.collect(openedAfterHold)).map((told) => [told.caller, told]),
			);
			const running = runningWith({
				gates,
				callers,
				opening: await c.get(sessions),
				clock: c.clock,
				log: c.log,
			});
			return {
				achievable: (amr) => amr.every((name) => provable.has(name)),
				returnAllowed,
				...running,
			};
		}),
	],
);
