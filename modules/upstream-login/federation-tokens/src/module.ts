import { metadataSections } from "@mod/clients";
import { routes } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { resealers } from "@mod/seal";
import { participants } from "@mod/session-participants";
import { upstreamLoginReceivers, upstreams } from "@mod/upstreams";
import { upstreamEndSessions } from "./contract.ts";
import { endSessionAt } from "./end-session.ts";
import { type Renewal, renewalIn } from "./renewal/renewal.ts";
import { clientSection, routesIn } from "./routes/routes.ts";
import { section } from "./section.ts";
import { upstreamTokenStore } from "./store.ts";
import { resealerOver } from "./vault/resealer.ts";
import { vaultFrom } from "./vault/vault.ts";

const name = "federation-tokens";
/** The one keeper the routes, the receiver and the participant share, built once. */
const kept = contract<Renewal>("federation-tokens.kept");

export default defineModule({ name, section }, (m) => [
	m.contribute(metadataSections).by(() => clientSection),
	m
		.contribute(resealers)
		.by(async (c) => resealerOver(await c.get(upstreamTokenStore), await vaultFrom(c))),
	m.provide(kept).by(renewalIn),
	m.contribute(upstreamLoginReceivers).by(async (c) => {
		const keeper = await c.get(kept);
		return {
			name,
			received: ({ session, idp, tokens }) => keeper.receive(session.id, idp, tokens),
			withdrawn: keeper.withdraw,
		};
	}),
	m.provide(upstreamEndSessions).by(async (c) => {
		const keeper = await c.get(kept);
		const known = await c.get(upstreams);
		return {
			of: async (session, back) => {
				const first = await keeper.first(session);
				return first && endSessionAt(known, first.idp, first.idToken, back, c.log);
			},
		};
	}),
	m.contribute(participants).by(async (c) => {
		const keeper = await c.get(kept);
		return { name, closing: (session) => keeper.close(session.id) };
	}),
	m.contribute(routes).by(async (c) => routesIn(c, await c.get(kept))),
]);
