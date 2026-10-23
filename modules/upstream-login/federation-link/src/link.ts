import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type OriginEvidence, originEvidence } from "@mod/csrf";
import { type HttpResponse, jsonAnswer, noStore, site } from "@mod/http";
import type { BuildContext, Log } from "@mod/kernel";
import { type Sessions, sessions } from "@mod/session";
import { type Handoff, handoff, type Joined } from "@mod/upstream-handoff";
import type { UpstreamContinuation } from "@mod/upstreams";
import { type Users, users } from "@mod/users";
import { z } from "zod";
import events from "./audit-events.ts";
import type { Settings } from "./section.ts";

export interface LinkParts {
	readonly origin: Pick<OriginEvidence, "sameOrigin">;
	readonly sessions: Pick<Sessions, "enterFor" | "enter" | "entryOf">;
	readonly users: Pick<Users, "link" | "unlink">;
	readonly audit: Pick<Audit, "record">;
	readonly handoff: Pick<Handoff, "joined" | "withdrawn">;
	readonly log: Pick<Log, "warn">;
	/** The step-up page a start short of a requirement is told of, and the public origin it comes back on. */
	readonly stepUp?: { readonly page: string; readonly origin: string };
}

/** What a link keeps from its start: the session it is for, and its subject. */
const kept = z.strictObject({ session: z.string(), subject: z.string() });
const linkOf = (value: unknown) => {
	const read = kept.safeParse(value);
	return read.success ? read.data : undefined;
};

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
/** A header's value as a log may carry it: printable ASCII, cut short. */
const loggable = (value: string | undefined) =>
	(value ?? "").replace(/[^\x20-\x7e]/g, "").slice(0, 64);

/**
 * The step-up page for a start short of `requirement`, coming back to this start alone: spelled from
 * the public origin, the start's path and `link=1`, never from what the browser sent besides.
 */
const raisedAt = (stepUp: NonNullable<LinkParts["stepUp"]>, requirement: string, path: string) => {
	const raise = new URL(stepUp.page);
	raise.searchParams.set("requirement", requirement);
	raise.searchParams.set("redirect_to", `${stepUp.origin}${path}?link=1`);
	return raise.href;
};

export async function linkIn(c: BuildContext<Settings>): Promise<UpstreamContinuation> {
	const page = c.section["step-up-page"];
	const origin = (await c.get(site)).origin;
	return linkWith({
		origin: await c.get(originEvidence),
		sessions: await c.get(sessions),
		users: await c.get(users),
		audit: await c.get(audit),
		handoff: await c.get(handoff),
		log: c.log,
		...(page === undefined || origin === undefined ? {} : { stepUp: { page, origin } }),
	});
}

/** What an audit event of a link says besides its kind and IdP, each only when known. */
interface Recorded {
	readonly subject: string;
	readonly reason?: string | undefined;
	readonly source?: string | undefined;
	readonly userAgent?: string | undefined;
}

/** Where a link lands, with its cookies. */
const sent = (location: string, cookies: readonly string[]): HttpResponse => ({
	status: 302,
	headers: { ...noStore, location },
	cookies,
});

/** A round trip that links the upstream identity to the account logged in when it started. */
export function linkWith(p: LinkParts): UpstreamContinuation {
	const audited = declaredAudit(p.audit, events);
	const record = (outcome: "linked" | "link_refused", idp: string, at: Recorded) =>
		audited.record(`federation.identity.${outcome}`, {
			subject: at.subject,
			attributes: {
				idp,
				...(at.source === undefined ? {} : { source: at.source }),
				...(at.userAgent === undefined ? {} : { userAgent: at.userAgent }),
				...(at.reason === undefined ? {} : { reason: at.reason }),
			},
		});
	return {
		name: "link",
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
				const page = p.stepUp && raisedAt(p.stepUp, entry.requirement, request.path);
				const named = page === undefined ? {} : { page };
				return { answer: jsonAnswer(403, { ...said, requirement: entry.requirement, ...named }) };
			}
			const { id, context } = entry.session;
			return { kept: { session: id, subject: context.subject } };
		},
		failed: ({ idp: name, reason, kept: was, source, userAgent }) => {
			const link = linkOf(was);
			if (link) record("link_refused", name, { subject: link.subject, reason, source, userAgent });
		},
		complete: async (at) => {
			const { request, idp: name, upstreamLogin, lands, source, userAgent, cleared } = at;
			// Kept by this link's own start, so it is always there: a missing one is a broken round trip.
			const link = linkOf(at.kept);
			if (!link) throw new Error("a link's round trip names its session");
			const refused = (status: number, reason: string, error = reason) => {
				record("link_refused", name, { subject: link.subject, reason, source, userAgent });
				return jsonAnswer(status, { error }, { cookies: cleared });
			};
			// The browser in no session lets the recorded one decide (a posted answer carries no cookie);
			// one in another session logged in as someone else since.
			const current = await p.sessions.enter(request);
			if (current !== undefined && current.id !== link.session)
				return refused(401, "login_required");
			// At the level its start entered at, by its handle (a posted answer carries no cookie).
			const held = await p.sessions.entryOf(link.session, "credentials");
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
			/** Whether the session still enters at the start's level, as the subject the link is for. */
			const stillHeld = async () => {
				const again = await p.sessions.entryOf(link.session, "credentials");
				return again.kind === "entered" && again.session.context.subject === link.subject;
			};
			// A best-effort amends for a session closed meanwhile: what this request wrote is undone,
			// each step tried whatever the other does, and the first failure thrown after.
			const undo = async (joined?: Joined) => {
				const steps = await Promise.allSettled([
					linked === "linked"
						? p.users.unlink(link.subject, upstream).then((answer) => {
								if (answer === "fixed") p.log.warn("federation.link_kept_fixed", { idp: name });
							})
						: undefined,
					joined === undefined ? undefined : p.handoff.withdrawn(link.session, name, joined),
				]);
				const failed = steps.find((step) => step.status === "rejected");
				if (failed) throw failed.reason;
			};
			/** Undoes what was written and refuses where the session no longer holds; throws, undone, where it cannot tell. */
			const closedSince = async (joined?: Joined) => {
				let held: boolean;
				try {
					held = await stillHeld();
				} catch (error) {
					await undo(joined);
					throw error;
				}
				if (held) return undefined;
				await undo(joined);
				return refused(401, "session_closed_during_link", "login_required");
			};
			// Checked right after the link, so a session closed by then is handed no tokens.
			const closed = await closedSince();
			if (closed) return closed;
			let joined: Joined | undefined;
			if (upstreamLogin.tokens) {
				try {
					joined = await p.handoff.joined(
						{ id: link.session, context },
						name,
						upstreamLogin.tokens,
					);
				} catch (error) {
					// A join that fails as the session closes leaves no link behind; one that fails otherwise keeps it.
					if (!(await stillHeld().catch(() => false))) await undo();
					throw error;
				}
			}
			const closedAfter = await closedSince(joined);
			if (closedAfter) return closedAfter;
			return sent(lands, cleared);
		},
	};
}
