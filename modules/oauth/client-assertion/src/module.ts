import { authMethods, clients, metadataSections } from "@mod/clients";
import { externalJwt } from "@mod/external-jwt";
import { site } from "@mod/http";
import { issuer } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { tokenEndpointLocation } from "@mod/token-endpoint";
import { clientKeys, clientKeysIn, keysTakes } from "./keys/keys.ts";
import { assertionMethod } from "./method.ts";
import { section } from "./section.ts";
import { spentAssertions } from "./store.ts";

/** What the module takes: `clientKeysIn`'s, what the method is built over, the site, and the clients its start warns of. */
const takes = [
	...keysTakes,
	tokenEndpointLocation,
	spentAssertions,
	externalJwt,
	issuer,
	site,
	clients,
];

export default defineModule({ name: "client-assertion", section, takes }, (m) => [
	m.contribute(metadataSections).by((c) => clientKeysIn(c)),
	m.contribute(authMethods).by(async (c) => {
		const { url } = await c.get(tokenEndpointLocation);
		// A public origin is required, as written, though the token endpoint has a location without one.
		if ((await c.get(site)).origin === undefined || url === undefined) {
			return c.refuse("client-assertion", "the token endpoint's location needs a public origin");
		}
		// Told at each start, by client: an assertion such a client made for another authorization
		// server that names this one's token endpoint can be used here.
		const known = c.late(clients);
		c.onStart(() => {
			for (const client of known().registered()) {
				if (client.section(clientKeys)["accept-loose-audience"]) {
					c.log.warn("client-assertion.accept_loose_audience", { client: client.id });
				}
			}
		});
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
