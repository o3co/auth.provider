import { clients } from "@mod/clients";
import { composedGrants, grants, targets } from "@mod/grants";
import { routes, site, use } from "@mod/http";
import { metadata } from "@mod/issuer";
import { defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { unservedGrants } from "./allowed/allowed.ts";
import { composedRule } from "./built-in/targets.ts";
import { tokenEndpointLocation } from "./contract.ts";
import { endpointIn } from "./endpoint-in/endpoint-in.ts";
import { tokenPath } from "./route/endpoint.ts";
import { section } from "./section.ts";

/** A browser's public client may send a body's type and its DPoP proof, and read the nonce, the challenge and the wait. */
const cors = {
	headers: ["content-type", "dpop"],
	exposes: ["dpop-nonce", "www-authenticate", "retry-after"],
};

export default defineModule({ name: "token-endpoint", section }, (m) => [
	m.provide(targets).by(composedRule),
	m
		.provide(composedGrants)
		.by(async (c) => new Set((await c.collect(grants)).map((g) => g.grantType))),
	m.provide(tokenEndpointLocation).by(async (c) => {
		const { origin } = await c.get(site);
		return { url: origin === undefined ? undefined : new URL(tokenPath, origin).href };
	}),
	m.contribute(metadata).by(async (c) => ({
		name: "token_endpoint",
		value: (await c.get(tokenEndpointLocation)).url,
	})),
	// Exactly the grants the endpoint dispatches to, so a grant not contributed is never listed.
	m.contribute(metadata).by(async (c) => ({
		name: "grant_types_supported",
		value: (await c.collect(grants)).map((g) => g.grantType),
	})),
	m.contribute(metadata).by(async (c) => ({
		name: "token_endpoint_auth_methods_supported",
		value: (await c.get(clients)).methods(),
	})),
	m.contribute(metadata).by(async (c) => {
		const algorithms = (await c.get(clients)).signingAlgorithms();
		return {
			name: "token_endpoint_auth_signing_alg_values_supported",
			value: algorithms.length > 0 ? algorithms : undefined,
		};
	}),
	m.contribute(routes).by(async (c) => {
		const composed = await c.collect(grants);
		// A grant a registered client is allowed and nothing serves would go missing in silence.
		const unserved = unservedGrants(
			(await c.get(clients)).registered(),
			new Set(composed.map((g) => g.grantType)),
		);
		if (unserved.length > 0) return c.refuseAll(unserved);
		// The route has no own-site policy: it relies on each grant saying whether it reads a cookie.
		const silent = composed.filter((g) => g.readsAmbient !== "none" && g.readsAmbient !== "cookie");
		if (silent.length > 0) {
			return c.refuseAll(
				silent.map((g) => ({
					where: `grants:${g.grantType}`,
					reason: "declares neither readsAmbient none nor cookie",
				})),
			);
		}
		const endpoint = await endpointIn(c, composed);
		const window = { limit: c.section.requests, ms: c.section.window * 1000 };
		const uses = [use(requestsPerSource, { name: "token-endpoint", window })];
		// Each grant names the bodies it takes; the endpoint refuses the others.
		return {
			method: "POST",
			path: tokenPath,
			uses,
			crossSite:
				"Authorization is per grant; a grant that reads a cookie declares it and checks the origin itself.",
			takes: ["form", "json", "none"],
			cors,
			...endpoint,
		};
	}),
]);
