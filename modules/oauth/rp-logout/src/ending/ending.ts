import { type Client, clients } from "@mod/clients";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import { issuer } from "@mod/issuer";
import type { BuildContext, Log } from "@mod/kernel";
import { type IdTokenHints, idTokenHints } from "@mod/oidc";
import { sessions } from "@mod/session";
import { type Closed, type Closing, closingFrom, closingTakes } from "../closing/closing.ts";
import { type CarriedRequest, carriedParam, confirmPath, unavailable } from "../confirm/confirm.ts";
import type { LogoutReturn, UpstreamEnd } from "../contract.ts";
import { frontChannelPage, returnUrl } from "../page/page.ts";
import { returnsTo } from "../registration/registration.ts";
import type { Settings } from "../section.ts";

export interface EndingParts {
	readonly hints: IdTokenHints;
	/** The handle of the session the browser's cookie opens, to tell whether the hint names it. */
	readonly sessions: { handleOf(request: HttpRequest): Promise<string | undefined> };
	/** The confirmation's carried request: signed for a request carried on, and checked when it comes back. */
	readonly confirm: {
		carry(request: CarriedRequest): Promise<string>;
		carried(token: string | undefined): Promise<CarriedRequest | undefined>;
		current(request: Pick<CarriedRequest, "client" | "back">): Promise<LogoutReturn>;
	};
	/** The logout's own path, which a hinted `POST` sends the browser on to as a `GET`. */
	readonly path: string;
	readonly clients: { find(id: string): Promise<Client | undefined> };
	/** The close the confirmation shares. */
	readonly closing: Closing;
	readonly issuer: string;
	/** The deployment's page a browser's refused request is sent to; none, and every refusal is JSON. */
	readonly errorPage?: string;
	readonly now: () => number;
	readonly log: Log;
}

const loggedOut = (cookies: readonly string[]) =>
	jsonAnswer(200, { logged_out: true }, { cookies });
/** A refusal of the request, answered as JSON, or on the deployment's error page to a browser where it has one. */
interface Refusal {
	readonly error: string;
	readonly description: string;
}
const refused = (error: string, description: string): Refusal => ({ error, description });
const unverified = refused("invalid_token", "id_token_hint verification failed");
const repeated = refused("invalid_request", "repeated parameter");
const mismatched = refused(
	"invalid_request",
	"client_id is not the client the id_token_hint was issued to",
);
const unregistered = refused(
	"invalid_request",
	"post_logout_redirect_uri is not registered for the client",
);
const carriedWithOthers = refused(
	"invalid_request",
	"request is sent with other logout parameters",
);
const carriedNotValid = refused("invalid_request", "request is not valid");
const sessionless = refused("invalid_request", "id_token_hint names no session");
/** What a hinted request names; none comes beside a carried request. */
const hinted = ["id_token_hint", "client_id", "post_logout_redirect_uri", "state"];
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

export function endingOver(p: EndingParts) {
	const { closing } = p;
	/**
	 * The return asked, where the hint's one client registered it exactly; `false` where it did not,
	 * a request refused whole. A record that cannot be read is passed on: whether the return may be
	 * taken cannot be told, so nothing is closed.
	 */
	const returnOf = async (id: string | undefined, asked: string | undefined) => {
		if (!asked) return undefined;
		if (id === undefined) return false;
		return returnsTo(await p.clients.find(id), asked) ? asked : false;
	};
	/** A refusal: to a browser, on to the error page where the deployment has one, its words in the query; else JSON. */
	const refuse = (request: HttpRequest, refusal: Refusal): HttpResponse => {
		if (p.errorPage === undefined || !wantsPage(request)) {
			return jsonAnswer(400, { error: refusal.error, error_description: refusal.description });
		}
		const location = new URL(p.errorPage);
		location.searchParams.set("error", refusal.error);
		location.searchParams.set("error_description", refusal.description);
		return { status: 303, headers: { ...noStore, location: location.href } };
	};
	/** On to `to`, carrying `token` where there is one. */
	const onTo = (to: string, token?: string): HttpResponse => {
		const location =
			token === undefined ? to : `${to}?${new URLSearchParams({ [carriedParam]: token })}`;
		return { status: 303, headers: { ...noStore, location } };
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
		if (values.repeated().length > 0) return refuse(request, repeated);
		const token = request.method === "GET" ? values.single(carriedParam) : undefined;
		if (token !== undefined) return resumed(request, token);
		const hint = values.single("id_token_hint");
		if (!hint) {
			// Without a hint the person is asked whether to log out (RP-Initiated Logout 1.0 §2), on this
			// site, where their session's cookie is sent. No client or return is read: without a hint
			// either is anyone's to write, so the confirmation ends on this site and never redirects (§3).
			return onTo(confirmPath);
		}
		const checked = await p.hints.check(hint);
		if (checked.kind === "sessionless") {
			return refuse(request, sessionless);
		}
		if (checked.kind === "invalid") return refuse(request, unverified);
		if (p.now() - checked.issuedAt > confirmAfterMs) return refuse(request, unverified);
		// A client_id beside the hint names the client the token was issued to, or the request is refused.
		const named = values.single("client_id");
		if (named && named !== checked.client) return refuse(request, mismatched);
		const state = values.single("state") || undefined;
		const back = await returnOf(checked.client, values.single("post_logout_redirect_uri"));
		if (back === false) return refuse(request, unregistered);
		const carried: CarriedRequest = {
			sid: checked.session,
			...(checked.client === undefined ? {} : { client: checked.client }),
			back: {
				...(back ? { postLogoutRedirectUri: back } : {}),
				...(state === undefined ? {} : { state }),
			},
		};
		// A POST from the client's site carries no SameSite=Lax cookie: the request is carried on to this
		// route's GET, a navigation that carries it, and judged there. The hint itself goes no further.
		if (request.method === "POST") return onTo(p.path, await p.confirm.carry(carried));
		return settled(request, carried, checked.subject);
	};
	/**
	 * A checked request, closed without asking only where its session is the one this browser holds
	 * (RP-Initiated Logout 1.0 §2). Another's, or none, has the person asked, the request carried on
	 * by `token` (made here where not given) and its session left open.
	 */
	const settled = async (
		request: HttpRequest,
		carried: CarriedRequest,
		subject?: string,
		token?: string,
	): Promise<HttpResponse> => {
		const { sid, back } = carried;
		if ((await p.sessions.handleOf(request)) !== sid) {
			return onTo(confirmPath, token ?? (await p.confirm.carry(carried)));
		}
		const closed = await closing(request, {
			sid,
			...(subject === undefined ? {} : { subject }),
			back,
		});
		if (closed.kind === "unavailable") return unavailable;
		if (closed.kind === "pending")
			return jsonAnswer(503, { error: "temporarily_unavailable" }, { cookies: closed.cookies });
		if (closed.kind === "not-this-logout") return loggedOut(closed.cookies);
		return answer(request, closed, sid, closed.upstream ?? returnUrl(back));
	};
	/** A carried request coming back as a GET: alone, it is checked as the confirmation checks it, and settled. */
	const resumed = async (request: HttpRequest, token: string): Promise<HttpResponse> => {
		if (hinted.some((name) => request.query.single(name) !== undefined))
			return refuse(request, carriedWithOthers);
		const carried = await p.confirm.carried(token);
		if (!carried) return refuse(request, carriedNotValid);
		// Its return is held to the client's registration as it is now, not as it was when carried.
		return settled(
			request,
			{ ...carried, back: await p.confirm.current(carried) },
			undefined,
			token,
		);
	};
	// A check that cannot tell throws Unavailable on, which the route's declared answer answers.
	return end;
}

/** What `endingFrom` takes from the composition. */
export const endingTakes = [idTokenHints, sessions, clients, issuer, ...closingTakes] as const;

/** The route's handler, from the composition's contracts, the confirmation's carried request and the route's path. */
export async function endingFrom(
	c: BuildContext<Settings>,
	upstream: UpstreamEnd | undefined,
	confirm: EndingParts["confirm"],
	path: string,
) {
	return endingOver({
		confirm,
		path,
		hints: await c.get(idTokenHints),
		sessions: await c.get(sessions),
		clients: await c.get(clients),
		closing: await closingFrom(c, upstream),
		issuer: (await c.get(issuer)).url,
		...(c.section["error-page"] === undefined ? {} : { errorPage: c.section["error-page"] }),
		now: c.clock.now,
		log: c.log,
	});
}
