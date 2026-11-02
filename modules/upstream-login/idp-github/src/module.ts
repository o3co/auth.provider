import { defineModule } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import { outboundRefusals } from "@mod/outbound-policy";
import { idpType, idpTypes } from "@mod/upstreams";
import { settingsOf } from "./settings.ts";
import { opened } from "./upstream.ts";

export default defineModule(
	// Safe on many instances given the same settings on each (deployment-guarantees, Several instances).
	{ name: "idp-github", replicaSafe: true, takes: [outbound, outboundRefusals] },
	(m) => [
		m.contribute(idpTypes).by(async (c) => {
			const out = await c.get(outbound);
			const settings = settingsOf(await c.get(outboundRefusals));
			return idpType({ type: "github", settings, open: async (read) => opened(read, out) });
		}),
	],
);
