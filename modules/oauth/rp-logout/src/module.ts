import { metadataSections } from "@mod/clients";
import { type HttpRequest, type HttpResponse, routes, site, use } from "@mod/http";
import { metadata } from "@mod/issuer";
import { contract, defineModule } from "@mod/kernel";
import { outboundRefusals } from "@mod/outbound-policy";
import { requestsPerSource } from "@mod/rate-limit";
import { participants } from "@mod/session-participants";
import { upstreamEnds } from "./contract.ts";
import { endingFrom, endingTakes } from "./ending/ending.ts";
import { type Notices, noticesFrom, noticesTakes } from "./notices/notices.ts";
import { remembering, rememberingTakes } from "./redemptions/redemptions.ts";
import { registrationIn } from "./registration/registration.ts";
import { section } from "./section.ts";

type Handler = (request: HttpRequest) => Promise<HttpResponse>;

const name = "rp-logout";
const path = "/oauth/logout";
/** The one set of notices the participant and the sweep share, built once. */
const shared = contract<Notices>("rp-logout.notices");
/** The one handler both methods of the route share, built once. */
const ending = contract<Handler>("rp-logout.ending");

export default defineModule(
	{
		name,
		section,
		replicaSafe: true,
		takes: [
			upstreamEnds,
			site,
			outboundRefusals,
			...noticesTakes,
			...endingTakes,
			...rememberingTakes,
		],
	},
	(m) => [
		m.contribute(metadataSections).by(registrationIn),
		remembering(m, name),
		m.provide(shared).by(async (c) => {
			const notices = await noticesFrom(c);
			c.every(c.section["sweep-interval"] * 1000, async () => {
				const { failed } = await notices.sweep();
				if (failed > 0) c.log.warn("rp-logout.notices_kept", { count: failed });
			});
			return notices;
		}),
		m.contribute(participants).by(async (c) => {
			const notices = await c.get(shared);
			const running = new Set<Promise<void>>();
			c.onStop(async () => {
				await Promise.all(running);
			});
			return {
				name,
				// Answers once every notice is kept; the first try goes on after, and the sweep takes what it leaves.
				closing: async (session) => {
					const trying = notices.deliver(await notices.closing(session));
					running.add(trying);
					// deliver never rejects, so the try left running ends without an unhandled rejection.
					void trying.then(() => running.delete(trying));
				},
			};
		}),
		m.provide(ending).by(async (c) => {
			const ends = await c.collect(upstreamEnds);
			if (ends.length > 1) return c.refuse(name, "more than one upstream end of session");
			return endingFrom(c, ends[0]);
		}),
		...(["GET", "POST"] as const).map((method) =>
			m.contribute(routes).by(async (c) => ({
				method,
				path,
				// OpenID Connect RP-Initiated Logout 1.0 §2: a POST is a form.
				takes: ["form", "none"],
				// It closes the session even on a GET, so a HEAD is not answered as one.
				...(method === "GET" ? { changesState: true } : {}),
				crossSite:
					"RP-initiated logout is a navigation from the RP's site by design; it closes only the session that a hint the provider signed names.",
				// Counted before any hint is checked, which reads keys and the store.
				uses: [
					use(requestsPerSource, {
						name: "rp-logout",
						window: { limit: c.section.requests, ms: c.section.window * 1000 },
					}),
				],
				handle: await c.get(ending),
			})),
		),
		m.contribute(metadata).by(async (c) => {
			const origin = (await c.get(site)).origin;
			return { name: "end_session_endpoint", value: origin && `${origin}${path}` };
		}),
		...[
			"frontchannel_logout_supported",
			"frontchannel_logout_session_supported",
			"backchannel_logout_supported",
			"backchannel_logout_session_supported",
		].map((item) => m.contribute(metadata).by(() => ({ name: item, value: true }))),
	],
);
