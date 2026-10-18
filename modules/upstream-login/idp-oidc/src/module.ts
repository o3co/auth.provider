import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { outbound, outboundPolicy } from "@mod/outbound";
import { idpType, idpTypes } from "@mod/upstreams";
import { settingsOf } from "./settings.ts";
import { opened } from "./upstream.ts";

export default defineModule({ name: "idp-oidc" }, (m) => [
	m.contribute(idpTypes).by(async (c) => {
		const reach = { outbound: await c.get(outbound), policy: await c.get(outboundPolicy) };
		const jwt = await c.get(externalJwt);
		return idpType({
			type: "oidc",
			settings: settingsOf(jwt.algorithms, reach.policy),
			open: (read, { idp }) => opened(read, reach, jwt, { clock: c.clock, log: c.log, idp }),
		});
	}),
]);
