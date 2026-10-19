import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type Client, clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import { issuer } from "@mod/issuer";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { type IdTokenHints, idTokenHints } from "@mod/oidc";
import { determinedSource } from "@mod/request-source";
import { type CloseOutcome, sessions } from "@mod/session";
import events from "../audit-events.ts";
import type { LogoutReturn, UpstreamEnd } from "../contract.ts";
import { type Frame, frontChannelPage } from "../page/page.ts";
import { framable, registration } from "../registration/registration.ts";
import type { Settings } from "../section.ts";
import { type SessionClients, sessionClients } from "../store.ts";

export interface EndingParts {
	readonly hints: IdTokenHints;
	readonly clients: { find(id: string): Promise<Client | undefined> };
	readonly sessions: {
		stillOpen(id: string): Promise<boolean>;
		close(id: string, request: HttpRequest): Promise<CloseOutcome>;
	};
	readonly sessionClients: Pick<SessionClients, "members">;
	readonly upstream: UpstreamEnd | undefined;
	readonly audit: Audit;
	readonly issuer: string;
	readonly now: () => number;
	readonly log: Log;
}

const loggedOut = (cookies: readonly string[]) =>
	jsonAnswer(200, { logged_out: true }, { cookies });
const refused = (error: string, description: string) =>
	jsonAnswer(400, { error, error_description: description });
const unverified = refused("invalid_token", "id_token_hint verification failed");
const unavailable = jsonAnswer(503, { error: "temporarily_unavailable" });
/** On a GET, a hint issued longer ago than this is refused, as a logout another site may have started. */
const confirmAfterMs = 86_400_000;

/** The q a media range gives `type`, the most specific range first; 0 when none names it. */
const qualityOf = (accept: string, type: string) => {
	const [major] = type.split("/");
	const ranges = accept.split(",").map((part) => {
		const [range = "", ...params] = part.split(";").map((s) => s.trim().toLowerCase());
		const q = params.find((p) => p.startsWith("q="));
		return { range, q: q === undefined ? 1 : Number(q.slice(2)) || 0 };
	});
	for (const name of [type, `${major}/*`, "*/*"]) {
		const found = ranges.find((r) => r.range === name);
		if (found) return found.q;
	}
	return 0;
};
/** A page only when the browser prefers HTML to JSON; on a tie, JSON. */
const wantsPage = (request: HttpRequest) => {
	const accept = request.headers.get("accept") ?? "*/*";
	return qualityOf(accept, "text/html") > qualityOf(accept, "application/json");
};
const withState = (uri: string, state: string | undefined) => {
	if (state === undefined) return uri;
	const url = new URL(uri);
	url.searchParams.set("state", state);
	return url.href;
};

export function endingOver(p: EndingParts) {
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
	/** The return the client registered, by exact match; none otherwise. */
	const returnOf = async (id: string | undefined, asked: string | undefined) => {
		if (id === undefined || !asked) return undefined;
		const client = await clientOf(id);
		const listed = client?.section(registration)["post-logout-redirect-uris"] ?? [];
		return listed.includes(asked) ? asked : undefined;
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
	/** The close's outcome, or none when it threw. */
	const closeOf = async (sid: string, request: HttpRequest) => {
		try {
			return await p.sessions.close(sid, request);
		} catch {
			return undefined;
		}
	};
	/** Where the browser goes after a logout, in order: the front-channel page, the upstream or the return, then JSON. */
	const answer = async (
		request: HttpRequest,
		closed: {
			readonly sid: string;
			readonly held: readonly string[];
			readonly cookies: readonly string[];
		},
		next: string | undefined,
	): Promise<HttpResponse> => {
		const { sid, held, cookies } = closed;
		const page = wantsPage(request)
			? frontChannelPage(await framesOf(held), { issuer: p.issuer, session: sid, next })
			: undefined;
		if (page) {
			if (page.skipped > 0) p.log.warn("rp-logout.frames_skipped", { count: page.skipped });
			const pageHeaders = {
				...noStore,
				"content-type": "text/html; charset=utf-8",
			};
			return { status: 200, headers: pageHeaders, body: page.html, cookies, loads: page.loads };
		}
		if (next) return { status: 303, headers: { ...noStore, location: next }, cookies };
		return loggedOut(cookies);
	};

	const end = async (request: HttpRequest): Promise<HttpResponse> => {
		const values = request.method === "GET" ? request.query : request.fields;
		const hint = values.single("id_token_hint");
		if (!hint) return refused("invalid_request", "id_token_hint is required");
		const checked = await p.hints.check(hint);
		if (checked.kind === "sessionless") {
			return refused("invalid_request", "id_token_hint names no session");
		}
		if (checked.kind === "invalid") return unverified;
		if (request.method === "GET" && p.now() - checked.issuedAt > confirmAfterMs) return unverified;
		const state = values.single("state") || undefined;
		const back = await returnOf(checked.client, values.single("post_logout_redirect_uri"));
		const sid = checked.session;
		// Both read before the close: a store that cannot answer ends nothing, and the close forgets the upstream tokens.
		const held = (await p.sessionClients.members(sid)).map(({ member }) => member);
		const upstream = await endUpstream(sid, {
			...(back ? { postLogoutRedirectUri: back } : {}),
			...(state === undefined ? {} : { state }),
		});
		const source = determinedSource(request);
		const userAgent = request.headers.get("user-agent");
		const record = (
			kind: "logout.success" | "logout.cascade_failed",
			subject: string,
			more: Record<string, string> = {},
		) =>
			declaredAudit(p.audit, events).record(kind, {
				subject,
				attributes: {
					sid,
					...(source ? { source } : {}),
					...(userAgent ? { userAgent } : {}),
					...more,
				},
			});
		// A session already ended still has its close asked, for the cookie, but is no logout of its own.
		const open = await p.sessions.stillOpen(sid);
		const closed = await closeOf(sid, request);
		if (!closed) {
			record("logout.cascade_failed", checked.subject, { store: "session" });
			return unavailable;
		}
		const { cookies, session } = closed;
		if (!open || !session) return loggedOut(cookies);
		// Closing, but the tokens it holds live until the close is swept: not logged out yet, as logout answers it.
		if (closed.kind === "pending") {
			declaredAudit(p.audit, events).record("logout.close_pending", {
				subject: session.subject,
				attributes: { sid, ...(source ? { source } : {}) },
			});
			return jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies });
		}
		record("logout.success", session.subject);
		return answer(request, { sid, held, cookies }, upstream ?? (back && withState(back, state)));
	};
	return async (request: HttpRequest): Promise<HttpResponse> => {
		try {
			return await end(request);
		} catch (error) {
			if (!isUnavailable(error)) throw error;
			// Answered here, so http never sees it: logged by what failed.
			p.log.warn("rp-logout.unavailable", { what: error.what });
			return unavailable;
		}
	};
}

/** The route's handler, from the composition's contracts. */
export async function endingFrom(c: BuildContext<Settings>, upstream: UpstreamEnd | undefined) {
	return endingOver({
		hints: await c.get(idTokenHints),
		clients: await c.get(clients),
		sessions: await c.get(sessions),
		sessionClients: await c.get(sessionClients),
		upstream,
		audit: await c.get(audit),
		issuer: (await c.get(issuer)).url,
		now: c.clock.now,
		log: c.log,
	});
}
