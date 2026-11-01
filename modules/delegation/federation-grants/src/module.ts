import { audit } from "@mod/audit";
import { metadataSections } from "@mod/clients";
import { csrfChecked } from "@mod/csrf";
import { routes, use } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { returnPaths } from "@mod/login-gates";
import { requestsPerSource } from "@mod/rate-limit";
import { resealers } from "@mod/seal";
import { revocationFollowers } from "@mod/subject-revocation";
import { apiOver, apiTakes, base } from "./api/api.ts";
import { followerOver, followerTakes } from "./api/follow.ts";
import { type GrantsBrowser, grantIntents, grantsBrowsers } from "./browser.ts";
import { clientSection } from "./grant/grant.ts";
import { recordsOver, shared, sharedOver, sharedTakes } from "./grant/shared.ts";
import { browserBase, intentsOver, intentsTakes } from "./intents/intents.ts";
import { resealerOver } from "./resealer.ts";
import { name, type Settings, section } from "./section.ts";
import { grantStore } from "./store.ts";
import { sweepIn, sweepTakes } from "./sweep/sweep.ts";

/** The requests a source may make in each window, on the client routes and the browser's alike. */
const windowOf = (settings: Settings) => ({
	limit: settings.requests,
	ms: settings.window * 1000,
});

export default defineModule(
	{
		name,
		// Safe on many instances: an end the store would not take is held by the instance that heard it alone,
		// which refuses until the held token ends (deployment-guarantees, Several instances); the sweep writes over
		// the version it read, so any number running it agree.
		replicaSafe: true,
		section,
		// Each helper names what it takes; the module's own factories take the grant store, audit and the browser half.
		takes: [
			...apiTakes,
			...followerTakes,
			...sharedTakes,
			...intentsTakes,
			...sweepTakes,
			grantStore,
			audit,
			grantsBrowsers,
		],
	},
	(m) => [
		m.contribute(metadataSections).by(() => clientSection),
		// A browser sent to log in, or to raise its session, comes back to the connect it opened.
		m.contribute(returnPaths).by(() => ({ path: `${browserBase}/connect` })),
		m.contribute(revocationFollowers).by(followerOver),
		m
			.contribute(resealers)
			.by(async (c) => resealerOver(await c.get(grantStore), await recordsOver(c))),
		m.provide(shared).by(async (c) => {
			const parts = await sharedOver(c);
			// Built once, so one sweep runs on each host.
			await sweepIn(c, parts, await c.get(audit));
			return parts;
		}),
		m.provide(grantIntents).by(intentsOver),
		...[base, `${base}/*`].map((path) =>
			m.contribute(routes).by(async (c) => ({
				method: "POST" as const,
				path,
				uses: [use(requestsPerSource, { name, window: windowOf(c.section) })],
				crossSite:
					"A confidential client's own call, authenticated as that client; it reads no cookie.",
				takes: ["json", "form"] as const,
				handle: await apiOver(c),
			})),
		),
		...(
			[
				[
					"GET",
					"connect",
					"connect",
					{
						changesState: true,
						crossSite:
							"A navigation the client sends the user on, carrying a request only that client could make.",
					},
				],
				["GET", "consent", "question", { changesState: false }],
				["POST", "consent", "decide", {}],
				[
					"GET",
					"callback/*",
					"callback",
					{
						changesState: true,
						crossSite:
							"The upstream's redirect back, matched to the state of a connection this browser started.",
					},
				],
			] as const
		).map(([method, path, step, declared]) =>
			m.contribute(routes).by(async (c) => {
				const window = windowOf(c.section);
				const limited = use(requestsPerSource, { name: `${name}.browser`, window });
				return {
					method,
					path: `${browserBase}/${path}`,
					// Another site's post is refused before it is counted, so it spends no source's count.
					uses: method === "POST" ? [use(csrfChecked), limited] : [limited],
					...declared,
					// The one browser half contributed, by federation-grants-connect.
					handle: ((await c.collect(grantsBrowsers))[0] as GrantsBrowser)[step],
				};
			}),
		),
	],
);
