import { metadataSections } from "@mod/clients";
import { csrfChecked } from "@mod/csrf";
import { routes, use } from "@mod/http";
import { defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { resealers } from "@mod/seal";
import { revocationFollowers } from "@mod/subject-revocation";
import { apiOver, base } from "./api/api.ts";
import { followerOver } from "./api/follow.ts";
import { browser, browserBase, connectOver } from "./connect/connect.ts";
import { clientSection } from "./grant/grant.ts";
import { recordsOver, shared, sharedOver } from "./grant/shared.ts";
import { resealerOver } from "./resealer.ts";
import { name, type Settings, section } from "./section.ts";
import { grantStore } from "./store.ts";

/** The requests a source may make in each window, on the client routes and the browser's alike. */
const windowOf = (settings: Settings) => ({
	limit: settings.requests,
	ms: settings["window-seconds"] * 1000,
});

export default defineModule({ name, section }, (m) => [
	m.contribute(metadataSections).by(() => clientSection),
	m.contribute(revocationFollowers).by(followerOver),
	m
		.contribute(resealers)
		.by(async (c) => resealerOver(await c.get(grantStore), await recordsOver(c))),
	m.provide(shared).by(sharedOver),
	m.provide(browser).by(connectOver),
	...[base, `${base}/*`].map((path) =>
		m.contribute(routes).by(async (c) => ({
			method: "POST" as const,
			path,
			uses: [use(requestsPerSource, { name, window: windowOf(c.section) })],
			takes: ["json", "form"] as const,
			handle: await apiOver(c),
		})),
	),
	...(
		[
			["GET", "connect", "connect"],
			["GET", "consent", "question"],
			["POST", "consent", "decide"],
			["GET", "callback/*", "callback"],
		] as const
	).map(([method, path, step]) =>
		m.contribute(routes).by(async (c) => {
			const window = windowOf(c.section);
			const limited = use(requestsPerSource, { name: `${name}.browser`, window });
			return {
				method,
				path: `${browserBase}/${path}`,
				uses: method === "POST" ? [limited, use(csrfChecked)] : [limited],
				handle: (await c.get(browser))[step],
			};
		}),
	),
]);
