import { type Clients, clients } from "@mod/clients";
import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { revocations } from "@mod/subject-revocation";
import { exchangeVerifiers } from "@mod/token-exchange";
import { upstreamNames, users } from "@mod/users";
import { idTokenChecks, usedIdTokens } from "./contract.ts";
import { fixedIssuers, type Issuers } from "./issuers.ts";
import { kinds, type Settings, section } from "./section.ts";
import { idTokenChecksOver, idTokens, type Taken } from "./verifier.ts";

/** Where the section names a client that is not registered, the first such; none when every one is. */
async function unknownClientIn(s: Settings, known: Pick<Clients, "find">) {
	for (const kind of kinds) {
		for (const id of Object.keys(s[kind]?.clients ?? {})) {
			if ((await known.find(id)) === undefined) return `exchange-id-tokens.${kind}.clients.${id}`;
		}
	}
	return undefined;
}

/** The module over the given issuers; the composed one is over the fixed issuers alone. */
export const exchangeIdTokensOver = (issuers: Issuers) =>
	defineModule(
		{
			name: "exchange-id-tokens",
			replicaSafe: true,
			section,
			// The verifiers are contributed, not collected, so they are not named.
			takes: [clients, externalJwt, users, revocations, usedIdTokens, idTokenChecks],
		},
		(m) => [
			// Each kind taken, under its upstream's name and issuer, so users counts it once among every module's.
			m.contribute(upstreamNames).by((c) => ({
				declaredBy: "exchange-id-tokens",
				names: kinds.flatMap((kind) => {
					const settings = c.section[kind];
					return settings === undefined
						? []
						: [{ name: settings.upstream, issuer: issuers[kind].iss[0] }];
				}),
			})),
			// The checks any grant takes them by; the exchange is one such grant.
			m.provide(idTokenChecks).by(async (c) => {
				const unknown = await unknownClientIn(c.section, await c.get(clients));
				if (unknown !== undefined) return c.refuse(unknown, "is no registered client");
				const jwt = await c.get(externalJwt);
				const skewMs = c.section["clock-skew"] * 1000;
				const taken: Taken[] = kinds.flatMap((kind) => {
					const settings = c.section[kind];
					if (settings === undefined) return [];
					const { iss, keys } = issuers[kind];
					return [
						{
							kind,
							upstream: settings.upstream,
							iss,
							jwt: jwt.verifierOf(keys, { algorithms: settings.algorithms, skewMs }),
							clients: Object.entries(settings.clients),
						},
					];
				});
				return idTokenChecksOver({
					taken,
					users: await c.get(users),
					revocations: await c.get(revocations),
					used: await c.get(usedIdTokens),
					now: c.clock.now,
					maxAgeMs: c.section["max-age"] * 1000,
					skewMs,
				});
			}),
			m.contribute(exchangeVerifiers).by(async (c) => idTokens(await c.get(idTokenChecks))),
		],
	);

export default exchangeIdTokensOver(fixedIssuers);
