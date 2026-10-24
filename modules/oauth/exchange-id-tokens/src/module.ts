import { clients } from "@mod/clients";
import { externalJwt } from "@mod/external-jwt";
import { defineModule } from "@mod/kernel";
import { revocations } from "@mod/subject-revocation";
import { exchangeVerifiers } from "@mod/token-exchange";
import { upstreamNames, users } from "@mod/users";
import { fixedIssuers, type Issuers } from "./issuers.ts";
import { kinds, section } from "./section.ts";
import { usedIdTokens } from "./store.ts";
import { idTokens, type Taken } from "./verifier.ts";

/** The module over the given issuers; the composed one is over the fixed issuers alone. */
export const exchangeIdTokensOver = (issuers: Issuers) =>
	defineModule(
		{
			name: "exchange-id-tokens",
			section,
			// The verifiers are contributed, not collected, so they are not named.
			takes: [clients, externalJwt, users, revocations, usedIdTokens],
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
			m.contribute(exchangeVerifiers).by(async (c) => {
				const known = await c.get(clients);
				for (const kind of kinds) {
					for (const id of Object.keys(c.section[kind]?.clients ?? {})) {
						if ((await known.find(id)) === undefined) {
							return c.refuse(
								`exchange-id-tokens.${kind}.clients.${id}`,
								"is no registered client",
							);
						}
					}
				}
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
							jwt: jwt.verifierOf(keys, { algorithms: ["RS256"], skewMs }),
							clients: Object.entries(settings.clients),
						},
					];
				});
				return idTokens({
					taken,
					users: await c.get(users),
					revocations: await c.get(revocations),
					used: await c.get(usedIdTokens),
					now: c.clock.now,
					maxAgeMs: c.section["max-age"] * 1000,
					skewMs,
				});
			}),
		],
	);

export default exchangeIdTokensOver(fixedIssuers);
