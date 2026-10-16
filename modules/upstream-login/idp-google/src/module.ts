import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { outbound, outboundPolicy } from "@mod/outbound";
import { idpType, idpTypes } from "@mod/upstreams";
import { settingsOf } from "./settings.ts";
import { opened } from "./upstream.ts";

export default defineModule({ name: "idp-google" }, (m) => [
	m.contribute(idpTypes).by(async (c) => {
		const out = await c.get(outbound);
		const jwt = await c.get(externalJwt);
		return idpType({
			type: "google",
			settings: settingsOf(await c.get(outboundPolicy)),
			open: async (read) => opened(read, out, jwt, { clock: c.clock }),
		});
	}),
]);
