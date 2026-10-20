import { type Audit, audit } from "@mod/audit";
import { type OriginEvidence, originEvidence } from "@mod/csrf";
import { jsonAnswer } from "@mod/http";
import type { BuildContext, Log } from "@mod/kernel";
import { type Sessions, sessions } from "@mod/session";
import { type Handoff, handoff } from "@mod/upstream-handoff";
import { type Users, users } from "@mod/users";
import {
	type Continuation,
	landingIn,
	type Recorded,
	recorderOf,
	sent,
} from "../round-trip/round-trip.ts";
import type { Settings } from "../section.ts";

export interface LinkParts {
	readonly origin: Pick<OriginEvidence, "sameOrigin">;
	readonly sessions: Pick<Sessions, "enterFor" | "enter" | "entryOf">;
	readonly users: Pick<Users, "link">;
	readonly audit: Pick<Audit, "record">;
	readonly handoff: Pick<Handoff, "joined" | "withdrawn">;
	readonly log: Pick<Log, "warn">;
	readonly landing: string;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
/** A header's value as a log may carry it: printable ASCII, cut short. */
const loggable = (value: string | undefined) =>
	(value ?? "").replace(/[^\x20-\x7e]/g, "").slice(0, 64);

export async function linkIn(c: BuildContext<Settings>): Promise<Continuation> {
	return linkWith({
		origin: await c.get(originEvidence),
		sessions: await c.get(sessions),
		users: await c.get(users),
		audit: await c.get(audit),
		handoff: await c.get(handoff),
		log: c.log,
		landing: await landingIn(c),
	});
}

/** A round trip that links the upstream identity to the account logged in when it started. */
export function linkWith(p: LinkParts): Continuation {
	const record: (outcome: "linked" | "link_refused", name: string, at: Recorded) => void =
		recorderOf(p.audit, "federation.identity");
	return {
		begin: async (request, name) => {
			// Only a navigation from this deployment's own page: another site cannot tie its identity here.
			if (!p.origin.sameOrigin(request)) {
				const secFetchSite = loggable(request.headers.get("sec-fetch-site"));
				p.log.warn("federation.link_start_rejected", { idp: name, secFetchSite });
				return { answer: jsonAnswer(403, { error: "link_requires_trusted_origin" }) };
			}
			const entry = await p.sessions.enterFor(request, "credentials");
			if (entry.kind === "absent") return { answer: jsonAnswer(401, { error: "login_required" }) };
			if (entry.kind === "short") {
				// The requirement's own answer, and its name.
				const said = isObject(entry.answer) ? entry.answer : { answer: entry.answer };
				return { answer: jsonAnswer(403, { ...said, requirement: entry.requirement }) };
			}
			const { id, context } = entry.session;
			return { carried: { link: { session: id, subject: context.subject } } };
		},
		failed: ({ name, reason, trip, source, userAgent }) => {
			// The round trip hands this a link's trip only; a login's has no subject to record.
			if (trip.link) {
				record("link_refused", name, {
					subject: trip.link.subject,
					reason,
					source,
					userAgent,
				});
			}
		},
		complete: async ({ request, name, upstreamLogin, trip, source, userAgent, cleared }) => {
			// Chosen by `trip.link`, so it is always there: a missing one is a broken round trip.
			const link = trip.link;
			if (!link) throw new Error("a link's trip names its session");
			const refused = (status: number, reason: string, error = reason) => {
				record("link_refused", name, { subject: link.subject, reason, source, userAgent });
				return jsonAnswer(status, { error }, { cookies: cleared });
			};
			// The browser in no session lets the recorded one decide (a posted answer carries no cookie);
			// one in another session logged in as someone else since.
			const current = await p.sessions.enter(request);
			if (current !== undefined && current.id !== link.session)
				return refused(401, "login_required");
			const held = await p.sessions.entryOf(link.session);
			// Short of a requirement is answered as closed, but recorded with its own reason.
			if (held.kind === "short") return refused(401, "session_short", "login_required");
			if (held.kind !== "entered" || held.session.context.subject !== link.subject) {
				return refused(401, "login_required");
			}
			const { context } = held.session;
			const upstream = { idp: name, subject: upstreamLogin.subject };
			const linked = await p.users.link(link.subject, upstream);
			if (linked === "conflict") return refused(409, "conflict", "identity_conflict");
			if (linked === "linked") record("linked", name, { subject: link.subject, source, userAgent });
			if (upstreamLogin.tokens) {
				const joined = await p.handoff.joined(
					{ id: link.session, context },
					name,
					upstreamLogin.tokens,
				);
				// Read again: a session closed, short of a requirement or logged in as someone else while
				// joining keeps none of the IdP's tokens, nor does one that cannot tell. Not `refused`: the
				// link stands, so no refusal is recorded.
				const stillHeld = async () => {
					try {
						const again = await p.sessions.entryOf(link.session);
						return again.kind === "entered" && again.session.context.subject === link.subject;
					} catch (error) {
						await p.handoff.withdrawn(link.session, name, joined);
						throw error;
					}
				};
				if (!(await stillHeld())) {
					await p.handoff.withdrawn(link.session, name, joined);
					return jsonAnswer(401, { error: "login_required" }, { cookies: cleared });
				}
			}
			return sent(trip.redirectTo ?? p.landing, cleared);
		},
	};
}
