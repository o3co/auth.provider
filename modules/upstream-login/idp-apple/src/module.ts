import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { outbound } from "@mod/outbound";
import { outboundRefusals } from "@mod/outbound-policy";
import { idpType, idpTypes } from "@mod/upstreams";
import { settingsOf } from "./settings.ts";
import { opened } from "./upstream.ts";

export default defineModule({ name: "idp-apple" }, (m) => [
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
]);
