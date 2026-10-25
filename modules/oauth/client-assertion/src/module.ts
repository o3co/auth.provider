import { authMethods, metadataSections } from "@mod/clients";
import { externalJwt } from "@mod/external-jwt";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { clientKeysIn, keysTakes } from "./keys/keys.ts";
import { assertionMethod } from "./method.ts";
import { section } from "./section.ts";
import { spentAssertions } from "./store.ts";

/** What the module takes: `clientKeysIn`'s, and what the method is built over. */
const takes = [...keysTakes, tokenEndpointLocation, spentAssertions, externalJwt, issuer];

export default defineModule({ name: "client-assertion", section, takes }, (m) => [
	m.contribute(metadataSections).by((c) => clientKeysIn(c)),
	m.contribute(authMethods).by(async (c) => {
		const { url } = await c.get(tokenEndpointLocation);
		if (url === undefined) {
			return c.refuse("client-assertion", "the token endpoint's location needs a public origin");
		}
		return assertionMethod({
			spent: await c.get(spentAssertions),
			jwt: await c.get(externalJwt),
			issuer: (await c.get(issuer)).url,
			tokenEndpoint: url,
			maxLifetimeMs: c.section["max-lifetime"] * 1000,
			skewMs: c.section["clock-skew"] * 1000,
			algorithms: c.section.algorithms,
			clock: c.clock,
			log: c.log,
		});
	}),
]);
