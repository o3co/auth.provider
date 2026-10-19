import { authMethods, metadataSections } from "@mod/clients";
import { externalJwt } from "@mod/external-jwt";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { outboundRefusals } from "@mod/outbound";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { clientKeysUnder } from "./keys.ts";
import { assertionMethod } from "./method.ts";
import { section } from "./section.ts";
import { spentAssertions } from "./store.ts";

export default defineModule({ name: "client-assertion", section }, (m) => [
	m.contribute(metadataSections).by(async (c) => clientKeysUnder(await c.get(outboundRefusals))),
	m.contribute(authMethods).by(async (c) => {
		const { url } = await c.get(tokenEndpointLocation);
		if (url === undefined) {
			return c.refuse("client-assertion", "the token endpoint's location needs a public origin");
		}
		return assertionMethod({
			spent: await c.get(spentAssertions),
			jwt: await c.get(externalJwt),
			audiences: [(await c.get(issuer)).url, url],
			maxLifetimeMs: c.section["max-lifetime"] * 1000,
			skewMs: c.section["clock-skew"] * 1000,
			clock: c.clock,
			log: c.log,
		});
	}),
]);
