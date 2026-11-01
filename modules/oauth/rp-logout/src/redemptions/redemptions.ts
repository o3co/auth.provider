import { sessionRedemptions } from "@mod/code-grant";
import type { Parts } from "@mod/kernel";
import { sessions } from "@mod/session";
import type { Settings } from "../section.ts";
import { sessionClients } from "../store.ts";

/** What `remembering`'s contribution takes from the composition (`sessions` late). */
export const rememberingTakes = [sessionClients, sessions] as const;

/**
 * The package's contribution, under `name`, to `code-grant`'s session redemptions: each client that
 * redeemed a code in a session is kept until the session ends, and at least `remember-for`.
 */
export const remembering = (m: Parts<Settings>, name: string) =>
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
	});
