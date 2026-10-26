import { type Audit, audit } from "@mod/audit";
import { type Client, clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import { issuer } from "@mod/issuer";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { type IdTokenHints, idTokenHints } from "@mod/oidc";
import { type CloseOutcome, type Entry, sessions } from "@mod/session";
import { type Closed, closingOver } from "../closing/closing.ts";
import type { UpstreamEnd } from "../contract.ts";
import { frontChannelPage } from "../page/page.ts";
import { registration } from "../registration/registration.ts";
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
const repeated = refused("invalid_request", "repeated parameter");
const mismatched = refused(
	"invalid_request",
	"client_id is not the client the id_token_hint was issued to",
);
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
	const closing = closingOver(p);
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
	/** Where the browser goes after a logout, in order: the front-channel page, the upstream or the return, then JSON. */
	const answer = async (
		request: HttpRequest,
		closed: Extract<Closed, { kind: "logged-out" }>,
		sid: string,
		next: string | undefined,
	): Promise<HttpResponse> => {
		const { cookies } = closed;
		const page = wantsPage(request)
			? frontChannelPage(await closed.frames(), { issuer: p.issuer, session: sid, next })
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
		// A value sent twice reads as none: refused first, so no check is passed by sending it twice.
		if (values.repeated().length > 0) return repeated;
		const hint = values.single("id_token_hint");
		if (!hint) return refused("invalid_request", "id_token_hint is required");
		const checked = await p.hints.check(hint);
		if (checked.kind === "sessionless") {
			return refused("invalid_request", "id_token_hint names no session");
		}
		if (checked.kind === "invalid") return unverified;
		if (p.now() - checked.issuedAt > confirmAfterMs) return unverified;
		// A client_id beside the hint names the client the token was issued to, or the request is refused.
		const named = values.single("client_id");
		if (named && named !== checked.client) return mismatched;
		const state = values.single("state") || undefined;
		const back = await returnOf(checked.client, values.single("post_logout_redirect_uri"));
		if (back === false) return unregistered;
		const sid = checked.session;
		const closed = await closing(request, {
			sid,
			subject: checked.subject,
			back: {
				...(back ? { postLogoutRedirectUri: back } : {}),
				...(state === undefined ? {} : { state }),
			},
		});
		if (closed.kind === "unavailable") return unavailable;
		if (closed.kind === "pending")
			return jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies: closed.cookies });
		if (closed.kind === "not-this-logout") return loggedOut(closed.cookies);
		return answer(request, closed, sid, closed.upstream ?? (back && withState(back, state)));
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
