import { audit } from "@mod/audit";
import { clients, metadataSections } from "@mod/clients";
import { routes, use } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { resealers } from "@mod/seal";
import { participants, sessions } from "@mod/session";
import { upstreamLoginReceivers, upstreams } from "@mod/upstreams";
import { callerFrom } from "./caller/caller.ts";
import { upstreamEndSessions } from "./contract.ts";
import { endSessionAt } from "./end-session.ts";
import { type Renewal, renewalWith } from "./renewal/renewal.ts";
import { base, clientSection, federationTokens } from "./routes.ts";
import { section } from "./section.ts";
import { refreshLocks, upstreamTokenStore } from "./store.ts";
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
	m.provide(kept).by(async (c) => {
		// Late: session collects this module's participant, which uses the keeper.
		const lateSessions = c.late(sessions);
		return renewalWith({
			store: await c.get(upstreamTokenStore),
			locks: await c.get(refreshLocks),
			upstreams: await c.get(upstreams),
			sessions: { entryOf: (handle, level) => lateSessions().entryOf(handle, level) },
			vault: await vaultFrom(c),
			clock: c.clock,
			random: c.random,
			log: c.log,
			refreshBeforeMs: c.section["refresh-before"] * 1000,
			maxLifetimeMs: c.section["max-lifetime"] * 1000,
			lockMs: c.section["lock-lifetime"] * 1000,
		});
	}),
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
	m.contribute(routes).by(async (c) => {
		const flow = {
			caller: await callerFrom(c),
			renewal: await c.get(kept),
			clients: await c.get(clients),
			upstreams: await c.get(upstreams),
			audit: await c.get(audit),
			log: c.log,
		};
		const window = { limit: c.section.requests, ms: c.section.window * 1000 };
		return {
			method: "POST",
			path: `${base}/*`,
			uses: [use(requestsPerSource, { name, window })],
			crossSite: "A client's own call, authenticated as that client; it reads no cookie.",
			handle: (request) => federationTokens(flow, request),
		};
	}),
]);
