import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type Client, clients } from "@mod/clients";
import type { HttpRequest } from "@mod/http";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { type CloseOutcome, sessions } from "@mod/session";
import events from "../audit-events.ts";
import type { LogoutReturn, UpstreamEnd } from "../contract.ts";
import type { Frame } from "../page/page.ts";
import { framable, registration } from "../registration/registration.ts";
import type { Settings } from "../section.ts";
import { type SessionClients, sessionClients } from "../store.ts";

export interface ClosingParts {
	readonly clients: { find(id: string): Promise<Client | undefined> };
	readonly sessions: { close(id: string, request: HttpRequest): Promise<CloseOutcome> };
	readonly sessionClients: Pick<SessionClients, "members">;
	readonly upstream: UpstreamEnd | undefined;
	readonly audit: Pick<Audit, "record">;
	readonly log: Log;
}

/** What a logout's close came to, for the route that asked it to answer. */
export type Closed =
	/** The session could not be closed; the failed close is recorded. */
	| { readonly kind: "unavailable" }
	/** The session is closing, its tokens live until the close is swept: no logout yet. */
	| { readonly kind: "pending"; readonly cookies: readonly string[] }
	/** One closed before, or gone: its close was asked, for the cookie, but it is no logout of its own. */
	| { readonly kind: "not-this-logout"; readonly cookies: readonly string[] }
	/** Logged out: the upstream's end of session if any, and the frames of the session's clients. */
	| {
			readonly kind: "logged-out";
			readonly cookies: readonly string[];
			readonly upstream: string | undefined;
			frames(): Promise<readonly Frame[]>;
	  };

/**
 * The close a logout asks, whichever route asked it: what the close forgets is read first (the
 * session's clients, the upstream's end of session), then the session closes, and the outcome is
 * recorded. Nothing reads the session before its close: a read can end one past its lifetime, and
 * the close would then call no participants; what the close found tells whether this is the logout.
 */
export function closingWith(p: ClosingParts) {
	/** The client's record, or none when it is gone or cannot be read; a logout goes on without it. */
	const clientOf = async (id: string) => {
		try {
			return await p.clients.find(id);
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			p.log.warn("rp-logout.client_unavailable", { client: id });
			return undefined;
		}
	};
	const framesOf = async (ids: readonly string[]) => {
		const frames: Frame[] = [];
		for (const id of ids) {
			const client = await clientOf(id);
			const registered = client?.section(registration);
			const uri = registered?.["frontchannel-logout-uri"];
			if (!client || !registered || uri === undefined) continue;
			// A client a source names was never checked at boot.
			if (!framable(registered, client)) {
				p.log.warn("rp-logout.frontchannel_off_redirects", { client: id });
				continue;
			}
			frames.push({ uri, withSession: registered["frontchannel-logout-session-required"] });
		}
		return frames;
	};
	/** The upstream's end of session, or none: the session still closes here, and the contributor logs its own failure. */
	const endUpstream = (session: string, back: LogoutReturn) =>
		Promise.resolve()
			.then(() => p.upstream?.at(session, back))
			.catch(() => undefined);
	/** The close's outcome, or none when it was unavailable; any other error is passed on, a mistake and no outage. */
	const closeOf = async (sid: string, request: HttpRequest) => {
		try {
			return await p.sessions.close(sid, request);
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			return undefined;
		}
	};

	return async (
		request: HttpRequest,
		at: {
			readonly sid: string;
			/** The subject the request named, for a close that fails before the session names one. */
			readonly subject?: string;
			readonly back: LogoutReturn;
		},
	): Promise<Closed> => {
		const { sid } = at;
		// Both read before the close: a store that cannot answer ends nothing, and the close forgets the upstream tokens.
		const held = (await p.sessionClients.members(sid)).map(({ member }) => member);
		const upstream = await endUpstream(sid, at.back);
		const source = determinedSource(request);
		const userAgent = request.headers.get("user-agent");
		const recorded = declaredAudit(p.audit, events);
		const closed = await closeOf(sid, request);
		if (!closed) {
			recorded.record("logout.cascade_failed", {
				...(at.subject === undefined ? {} : { subject: at.subject }),
				attributes: {
					sid,
					...(source ? { source } : {}),
					...(userAgent ? { userAgent } : {}),
					store: "session",
				},
			});
			return { kind: "unavailable" };
		}
		const { cookies, session } = closed;
		// Closing, but the tokens it holds live until the close is swept: not logged out yet, as logout
		// answers it. Asked before any answer of done, so a close sent again while pending is never one.
		if (closed.kind === "pending") {
			const subject = session?.subject ?? at.subject;
			recorded.record("logout.close_pending", {
				...(subject === undefined ? {} : { subject }),
				attributes: { sid, ...(source ? { source } : {}) },
			});
			return { kind: "pending", cookies };
		}
		// One closed before, or gone, still has its close asked, for the cookie, but is no logout of its own.
		if (!session || (closed.from !== "open" && closed.from !== "closing"))
			return { kind: "not-this-logout", cookies };
		recorded.record("logout.success", {
			subject: session.subject,
			attributes: { sid, ...(source ? { source } : {}), ...(userAgent ? { userAgent } : {}) },
		});
		return { kind: "logged-out", cookies, upstream, frames: () => framesOf(held) };
	};
}

export type Closing = ReturnType<typeof closingWith>;

/** What `closingFrom` takes from the composition. */
export const closingTakes = [clients, sessions, sessionClients, audit] as const;

/** The close, from the composition's contracts, for the route that asks one. */
export async function closingFrom(
	c: BuildContext<Settings>,
	upstream: UpstreamEnd | undefined,
): Promise<Closing> {
	return closingWith({
		clients: await c.get(clients),
		sessions: await c.get(sessions),
		sessionClients: await c.get(sessionClients),
		upstream,
		audit: await c.get(audit),
		log: c.log,
	});
}
