import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import { outboundRefusals } from "@mod/outbound-policy";
import { idpType, idpTypes } from "@mod/upstreams";
import { settingsOf } from "./settings.ts";
import { opened } from "./upstream.ts";

export default defineModule(
	// Safe on many instances given the same settings on each (deployment-guarantees, Several instances).
	{ name: "idp-google", replicaSafe: true, takes: [externalJwt, outbound, outboundRefusals] },
	(m) => [
		m.contribute(idpTypes).by(async (c) => {
			const out = await c.get(outbound);
			const jwt = await c.get(externalJwt);
			return idpType({
				type: "google",
				settings: settingsOf(await c.get(outboundRefusals)),
				open: async (read, { idp }) => opened(read, out, jwt, { clock: c.clock, log: c.log, idp }),
			});
		}),
	],
);
