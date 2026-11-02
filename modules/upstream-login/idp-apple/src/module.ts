import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import { outboundRefusals } from "@mod/outbound-policy";
import { idpType, idpTypes } from "@mod/upstreams";
import { settingsOf } from "./settings.ts";
import { opened } from "./upstream.ts";

export default defineModule(
	// Safe on many instances: each signs and keeps its own client secret for half its life; every one is valid.
	{ name: "idp-apple", replicaSafe: true, takes: [externalJwt, outbound, outboundRefusals] },
	(m) => [
		m.contribute(idpTypes).by(async (c) => {
			const out = await c.get(outbound);
			const jwt = await c.get(externalJwt);
			return idpType({
				type: "apple",
				settings: settingsOf(await c.get(outboundRefusals)),
				open: async (read, { redirectUri }) =>
					opened(read, out, jwt, { clock: c.clock, redirectUri }),
			});
		}),
	],
);
