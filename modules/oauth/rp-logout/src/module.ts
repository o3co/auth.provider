import { metadataSections } from "@mod/clients";
import { sessionRedemptions } from "@mod/code-grant";
import { type HttpRequest, type HttpResponse, routes, site, use } from "@mod/http";
import { metadata } from "@mod/issuer";
import { contract, defineModule } from "@mod/kernel";
import { requestsPerSource } from "@mod/rate-limit";
import { participants, sessions } from "@mod/session";
import { upstreamEnds } from "./contract.ts";
import { endingFrom } from "./ending/ending.ts";
import { type Notices, noticesFrom } from "./notices/notices.ts";
import { registration } from "./registration/registration.ts";
import { section } from "./section.ts";
import { sessionClients } from "./store.ts";

type Handler = (request: HttpRequest) => Promise<HttpResponse>;

const name = "rp-logout";
const path = "/oauth/logout";
/** The one set of notices the participant and the sweep share, built once. */
const shared = contract<Notices>("rp-logout.notices");
/** The one handler both methods of the route share, built once. */
const ending = contract<Handler>("rp-logout.ending");

export default defineModule({ name, section, replicaSafe: true }, (m) => [
	m.contribute(metadataSections).by(() => registration),
	m.contribute(sessionRedemptions).by(async (c) => {
		const held = await c.get(sessionClients);
		// Late: session's own build asks the participants, this module among them.
		const open = c.late(sessions);
		const rememberMs = c.section["remember-for"] * 1000;
		return {
			name,
			redeemed: async (session, client) => {
				// Kept until the session ends, so its close still tells the client.
				const entry = await open().entryOf(session);
				const untilEnd = entry.kind === "entered" ? entry.endsAt - c.clock.now() : 0;
				const { pushedOut } = await held.add(session, client, Math.max(rememberMs, untilEnd));
				if (pushedOut.length > 0)
					c.log.warn("rp-logout.clients_pushed_out", { count: pushedOut.length });
			},
		};
	}),
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
]);
