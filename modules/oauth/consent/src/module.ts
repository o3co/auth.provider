import { audit } from "@mod/audit";
import { documentCopies } from "@mod/client-documents";
import { clients, metadataSections } from "@mod/clients";
import { csrfChecked } from "@mod/csrf";
import { routes, site, use } from "@mod/http";
import { defineModule, Unavailable } from "@mod/kernel";
import { sessions } from "@mod/session";
import { loopbackPagesRefused } from "@mod/url-setting";
import { askKey, storedOf } from "./ask.ts";
import { clientCopy, clientSection, isFirstParty, underOf } from "./client-section.ts";
import { consents } from "./contract.ts";
import { grantsOver } from "./grants/grants.ts";
import { answerOver, path, showOver } from "./page/page.ts";
import { section } from "./section.ts";
import { httpsUrl, spaceOrControl } from "./shapes.ts";
import { askStore, grantStore } from "./store.ts";

/** A consent range: distinct strings, none empty, none holding whitespace or a control character. */
const isRange = (range: readonly string[]) =>
	range.every((r) => r !== "" && !spaceOrControl.test(r)) && new Set(range).size === range.length;

/** What its provision and its routes take; each is taken whatever the section says. */
const takes = [grantStore, askStore, site, sessions, clients, audit];

export default defineModule(
	{
		name: "consent",
		replicaSafe: true,
		section,
		// A page on the operator's own machine over plain http is for trying the app, never a deployment.
		refusedInProduction: (s) => loopbackPagesRefused({ page: s.page }),
		takes,
	},
	(m) => [
		m.contribute(metadataSections).by(() => clientSection),
		m.contribute(documentCopies).by(() => clientCopy),
		m.provide(consents).by(async (c) => {
			const grants = await grantsOver(c);
			const asks = await c.get(askStore);
			const origin = (await c.get(site)).origin;
			if (origin === undefined) return c.refuse("consent", "a public origin is required");
			// Told at every start by client: its users are never asked.
			for (const client of (await c.get(clients)).registered()) {
				if (isFirstParty(client)) c.log.warn("consent.first_party", { client: client.id });
			}
			/** Destinations are https URLs on this deployment's own origin; the caller made them. */
			const onOrigin = (url: string) => httpsUrl(url)?.origin === origin;
			const { page } = c.section;
			return {
				grantedFor: grants.rangeFor,
				coversFor: grants.covers,
				grantFor: grants.grant,
				asking: page !== undefined,
				askFor: async (session, client, asked) => {
					if (page === undefined) throw new TypeError("consent: no consent page is set to ask on");
					if (!onOrigin(asked.onAccept) || !onOrigin(asked.onDeny)) {
						throw new TypeError("consent: destinations must be https URLs on the public origin");
					}
					if (!isRange(asked.range)) {
						throw new TypeError("consent: a range is distinct strings without spaces or controls");
					}
					const challenge = Buffer.from(c.random.bytes(32)).toString("base64url");
					const lifetimeMs = c.section["challenge-lifetime"] * 1000;
					const under = underOf(client);
					const record = storedOf({
						...asked,
						clientId: client.id,
						range: [...asked.range],
						subject: session.context.subject,
						deadline: c.clock.now() + lifetimeMs,
						...(under === undefined ? {} : { under }),
					});
					const saved = await asks.save(askKey(session.id, challenge), record, lifetimeMs);
					if (saved !== "created") throw new Unavailable("consent");
					const sent = new URL(page);
					sent.searchParams.set("challenge", challenge);
					return sent.href;
				},
			};
		}),
		m.contribute(routes).by(async (c) => ({
			method: "GET",
			path,
			changesState: false,
			...(await showOver(c)),
		})),
		m.contribute(routes).by(async (c) => ({
			method: "POST",
			path,
			uses: [use(csrfChecked)],
			unlimited:
				"The user's session is authenticated; a per-source limit belongs to unauthenticated entries.",
			takes: ["form", "json"],
			...(await answerOver(c)),
		})),
	],
);
