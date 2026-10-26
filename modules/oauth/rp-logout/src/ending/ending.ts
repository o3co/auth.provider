import { type Audit, audit, declaredAudit } from "@mod/audit";
import { type Client, clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import { issuer } from "@mod/issuer";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { type IdTokenHints, idTokenHints } from "@mod/oidc";
import { determinedSource } from "@mod/request-source";
import { type CloseOutcome, type Entry, sessions } from "@mod/session";
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
		entryOf(id: string): Promise<Entry>;
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
const unregistered = refused(
	"invalid_request",
	"post_logout_redirect_uri is not registered for the client",
);
/** A hint issued longer ago than this is refused, by GET or POST, as a logout another site may have started. */
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
	/**
	 * The return asked, where the hint's one client registered it exactly; `false` where it did not,
	 * a request refused whole. A record that cannot be read is passed on: whether the return may be
	 * taken cannot be told, so nothing is closed.
	 */
	const returnOf = async (id: string | undefined, asked: string | undefined) => {
		if (!asked) return undefined;
		if (id === undefined) return false;
		const client = await p.clients.find(id);
		const listed = client?.section(registration)["post-logout-redirect-uris"] ?? [];
		return listed.includes(asked) ? asked : false;
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
		if (p.now() - checked.issuedAt > confirmAfterMs) return unverified;
		const state = values.single("state") || undefined;
		const back = await returnOf(checked.client, values.single("post_logout_redirect_uri"));
		if (back === false) return unregistered;
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
		// Nothing reads the session before its close: a read can end one past its lifetime, and the close
		// would then call no participants. What the close found tells whether this is the logout.
		const closed = await closeOf(sid, request);
		if (!closed) {
			record("logout.cascade_failed", checked.subject, { store: "session" });
			return unavailable;
		}
		const { cookies, session } = closed;
		// Closing, but the tokens it holds live until the close is swept: not logged out yet, as logout
		// answers it. Asked before any answer of done, so a close sent again while pending is never one.
		if (closed.kind === "pending") {
			declaredAudit(p.audit, events).record("logout.close_pending", {
				subject: session?.subject ?? checked.subject,
				attributes: { sid, ...(source ? { source } : {}) },
			});
			return jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies });
		}
		// One closed before, or gone, still has its close asked, for the cookie, but is no logout of its own.
		if (!session || (closed.from !== "open" && closed.from !== "closing"))
			return loggedOut(cookies);
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

/** What `endingFrom` takes from the composition. */
export const endingTakes = [
	idTokenHints,
	clients,
	sessions,
	sessionClients,
	audit,
	issuer,
] as const;

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
