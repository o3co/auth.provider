import { audit } from "@mod/audit";
import { type Clients, clients } from "@mod/clients";
import { routes, site, use } from "@mod/http";
import { issuer, metadata } from "@mod/issuer";
import { type BuildContext, defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { tokens } from "@mod/tokens";
import type { z } from "zod";
import { revocableKinds } from "./contract.ts";
import { introspection } from "./introspection.ts";
import { accessKind, revocation } from "./revocation.ts";
import { section } from "./section.ts";

const introspectPath = "/oauth/introspect";
const revokePath = "/oauth/revoke";
/** A public client's page may revoke its token (RFC 7009 §2.1), and read the challenge and the wait. */
const revokeCors = {
	headers: ["authorization", "content-type"],
	exposes: ["www-authenticate", "retry-after"],
};

/** Where a route answers, absolute on the public origin; nothing without one. */
const located = async (c: BuildContext<unknown>, path: string) => {
	const { origin } = await c.get(site);
	return origin === undefined ? undefined : new URL(path, origin).href;
};

/** Each route counts its own requests per source, in the window the section sets. */
const limited = (c: BuildContext<z.output<typeof section>>, name: string) => {
	const window = { limit: c.section.requests, ms: c.section.window * 1000 };
	return [use(requestsPerSource, { name: `token-control.${name}`, window })];
};

export default defineModule({ name: "token-control", section }, (m) => [
	m.contribute(routes).by(async (c) => ({
		method: "POST",
		path: introspectPath,
		uses: limited(c, "introspect"),
		...introspection(
			await c.get(clients),
			await c.get(tokens),
			(await c.get(issuer)).url,
			await c.get(audit),
		),
	})),
	m.contribute(routes).by(async (c) => {
		const contributed = await c.collect(revocableKinds);
		if (contributed.some((kind) => kind.hint === "access_token")) {
			return c.refuse("token-control", "token-control owns access token revocation");
		}
		return {
			method: "POST",
			path: revokePath,
			uses: limited(c, "revoke"),
			cors: revokeCors,
			...revocation(
				await c.get(clients),
				[accessKind(await c.get(tokens)), ...contributed],
				await c.get(audit),
			),
		};
	}),
	m.contribute(metadata).by(async (c) => ({
		name: "introspection_endpoint",
		value: await located(c, introspectPath),
	})),
	// Published only where some token can be revoked, though the route answers either way.
	m.contribute(metadata).by(async (c) => ({
		name: "revocation_endpoint",
		value: (await revocableIn(c)) ? await located(c, revokePath) : undefined,
	})),
	// RFC 8414 §2: left out, these would read as client_secret_basic alone. A public client may revoke its
	// own tokens (RFC 7009 §2.1), never introspect (RFC 7662 §2.1).
	m.contribute(metadata).by(async (c) => ({
		name: "introspection_endpoint_auth_methods_supported",
		value: (await c.get(clients)).methods().filter((method) => method !== "none"),
	})),
	m.contribute(metadata).by(async (c) => ({
		name: "introspection_endpoint_auth_signing_alg_values_supported",
		value: signedBy(await c.get(clients)),
	})),
	m.contribute(metadata).by(async (c) => ({
		name: "revocation_endpoint_auth_methods_supported",
		value: (await revocableIn(c)) ? (await c.get(clients)).methods() : undefined,
	})),
	m.contribute(metadata).by(async (c) => ({
		name: "revocation_endpoint_auth_signing_alg_values_supported",
		value: (await revocableIn(c)) ? signedBy(await c.get(clients)) : undefined,
	})),
]);

/** Whether some token can be revoked here. */
const revocableIn = async (c: BuildContext<unknown>) =>
	(await c.get(tokens)).revocable() || (await c.collect(revocableKinds)).length > 0;

/** The algorithms signed client credentials may use; none where no method signs. */
const signedBy = (registry: Clients) => {
	const algorithms = registry.signingAlgorithms();
	return algorithms.length > 0 ? algorithms : undefined;
};
