import { metadataSections } from "@mod/clients";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, routes, use } from "@mod/http";
import { endpointOrigin, issuer, metadata } from "@mod/issuer";
import { contract, defineModule } from "@mod/kernel";
import { outboundRefusals } from "@mod/outbound-policy";
import { requestsPerSource } from "@mod/rate-limit";
import { participants } from "@mod/session-participants";
import { loopbackPagesRefused } from "@mod/url-setting";
import { confirmFrom, confirmPath, confirmTakes, unavailable } from "./confirm/confirm.ts";
import { upstreamEnds } from "./contract.ts";
import { endingFrom, endingTakes } from "./ending/ending.ts";
import { type Notices, noticesFrom, noticesTakes } from "./notices/notices.ts";
import { remembering, rememberingTakes } from "./redemptions/redemptions.ts";
import { registrationIn } from "./registration/registration.ts";
import { type Settings, section } from "./section.ts";

type Handler = (request: HttpRequest) => Promise<HttpResponse>;

const name = "rp-logout";
const path = "/oauth/logout";
/** The one set of notices the participant and the sweep share, built once. */
const shared = contract<Notices>("rp-logout.notices");
/** The one handler both methods of the route share, built once. */
const ending = contract<Handler>("rp-logout.ending");
/** The confirmation's two handlers, built once. */
const confirming = contract<Awaited<ReturnType<typeof confirmFrom>>>("rp-logout.confirming");

/** The logout's own requests per source, which every route that may sign a confirmation is counted with. */
const counted = (c: { readonly section: Settings }) =>
	use(requestsPerSource, {
		name: "rp-logout",
		window: { limit: c.section.requests, ms: c.section.window * 1000 },
	});

export default defineModule(
	{
		name,
		section,
		replicaSafe: true,
		refusedInProduction: (s) => loopbackPagesRefused({ "error-page": s["error-page"] }),
		takes: [
			upstreamEnds,
			outboundRefusals,
			...noticesTakes,
			...endingTakes,
			...confirmTakes,
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
			return endingFrom(c, ends[0], await c.get(confirming), path);
		}),
		m.provide(confirming).by(async (c) => confirmFrom(c, (await c.collect(upstreamEnds))[0], path)),
		// The confirmation of a logout started without a hint (OpenID Connect RP-Initiated Logout 1.0 §2).
		m.contribute(routes).by(async (c) => ({
			method: "GET",
			path: confirmPath,
			changesState: false,
			// Each page signs a confirmation: counted with the logout's own requests.
			uses: [counted(c)],
			unavailable: { response: unavailable },
			handle: (await c.get(confirming)).show,
		})),
		m.contribute(routes).by(async (c) => ({
			method: "POST",
			path: confirmPath,
			takes: ["form"],
			// A POST without a valid confirmation asks again, signing another: counted as the page is, after
			// the CSRF check, which an own-site policy runs before any per-source one.
			uses: [use(csrfChecked), counted(c)],
			unavailable: { response: unavailable },
			handle: (await c.get(confirming)).take,
		})),
		...(["GET", "POST"] as const).map((method) =>
			m.contribute(routes).by(async (c) => ({
				method,
				path,
				// OpenID Connect RP-Initiated Logout 1.0 §2: a POST is a form.
				takes: ["form", "none"],
				// It closes the session even on a GET, so a HEAD is not answered as one.
				...(method === "GET" ? { changesState: true } : {}),
				crossSite:
					"RP-initiated logout is a navigation from the RP's site by design; without asking, it closes only the session the browser holds, where a hint the provider signed names it.",
				// Counted before any hint is checked, which reads keys and the store.
				uses: [counted(c)],
				unavailable: { response: unavailable },
				handle: await c.get(ending),
			})),
		),
		m.contribute(metadata).by(async (c) => {
			const origin = endpointOrigin(await c.get(issuer));
			return { name: "end_session_endpoint", value: `${origin}${path}` };
		}),
		...[
			"frontchannel_logout_supported",
			"frontchannel_logout_session_supported",
			"backchannel_logout_supported",
			"backchannel_logout_session_supported",
		].map((item) => m.contribute(metadata).by(() => ({ name: item, value: true }))),
	],
);
