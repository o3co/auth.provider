import { type Audit, declaredAudit } from "@mod/audit";
import { type OriginEvidence, originEvidence } from "@mod/csrf";
import type { HttpRequest, HttpResponse, Site, Values } from "@mod/http";
import { jsonAnswer, noStore, site } from "@mod/http";
import { type BuildContext, type Clock, contract, isUnavailable, type Log } from "@mod/kernel";
import { type Logins, logins } from "@mod/login-gates";
import { determinedSource } from "@mod/request-source";
import { type RoundTrips, roundTrips } from "@mod/upstream-round-trip";
import {
	type Kept,
	type Upstream,
	type UpstreamContinuation,
	type UpstreamLogin,
	UpstreamRefused,
	upstreamContinuations,
} from "@mod/upstreams";
import events from "../audit-events.ts";
import type { Settings } from "../section.ts";
import { carriedOf, type Trip, type TripCarried, toCarried, tripOf } from "./trip.ts";

export const base = "/session/oauth/federation";
/** Each IdP's own callback, named after it, so two never share one. */
export const callbackPath = (idp: string) => `${base}/${idp}/callback`;

/** One configured IdP, opened at boot. */
export interface Idp {
	readonly upstream: Upstream;
	readonly formPost: boolean;
	readonly redirectUri: string;
	readonly upstreamAmr: ReadonlyMap<string, string>;
	/** How long before a demand for a fresh login the upstream may say the user logged in. */
	readonly freshLoginAllowanceMs: number;
}

/** What the round trip hands a continuation once the upstream's answer is taken, exchanged and fresh. */
export interface Completing {
	readonly request: HttpRequest;
	readonly name: string;
	readonly idp: Idp;
	readonly upstreamLogin: UpstreamLogin;
	readonly trip: Trip;
	readonly source?: string;
	readonly userAgent?: string;
	/** The round trip's cookie, cleared: every answer from here on carries it. */
	readonly cleared: readonly string[];
}

/** Where a round trip goes once the upstream answers, when no continuation is chosen: the login. */
export interface Continuation {
	/** At the start: its refusal, or what the round trip carries for the callback. */
	begin(request: HttpRequest, name: string): Promise<{ answer: HttpResponse } | { kept?: Kept }>;
	complete(at: Completing): Promise<HttpResponse>;
	/** A refusal after the take and before `complete`, recorded as this continuation records them. */
	failed(at: {
		readonly name: string;
		readonly reason: string;
		readonly trip: Trip;
		readonly source?: string;
		readonly userAgent?: string;
	}): void;
}

export interface Flow {
	readonly idps: ReadonlyMap<string, Idp>;
	readonly trips: RoundTrips;
	readonly origin: Pick<OriginEvidence, "sameOrigin">;
	/** The return targets a login may name. */
	readonly logins: Pick<Logins, "returnAllowed">;
	readonly login: Continuation;
	/** The continuations a start may choose, by name. */
	readonly continuations: ReadonlyMap<string, UpstreamContinuation>;
	readonly clock: Clock;
	readonly log: Log;
	readonly landing: string;
	readonly tripMs: number;
}

/** What a federation login proves. */
export const proves = ["fed"];

/** What a federation audit event says besides its kind and IdP, each only when known. */
export interface Recorded {
	readonly subject?: string | undefined;
	readonly reason?: string | undefined;
	readonly source?: string | undefined;
	readonly userAgent?: string | undefined;
}
/** Records the events under a prefix in federation's words: the IdP as `idp`, the address as `source`. */
export const recorderOf = (audit: Pick<Audit, "record">, prefix: string) => {
	const audited = declaredAudit(audit, events);
	return (outcome: string, name: string, at: Recorded) =>
		audited.record(`${prefix}.${outcome}` as keyof typeof events, {
			...(at.subject === undefined ? {} : { subject: at.subject }),
			attributes: {
				idp: name,
				...(at.source === undefined ? {} : { source: at.source }),
				...(at.userAgent === undefined ? {} : { userAgent: at.userAgent }),
				...(at.reason === undefined ? {} : { reason: at.reason }),
			},
		});
};

export const sent = (location: string, cookies: readonly string[]): HttpResponse => ({
	status: 302,
	headers: { ...noStore, location },
	cookies,
});
export const landed = (location: string, cookies: readonly string[]): HttpResponse => ({
	status: 303,
	headers: { ...noStore, location },
	cookies,
});
/** What a start or a callback answers when a store or the upstream cannot tell, in OAuth's word. */
const unavailable = { error: "temporarily_unavailable" };
export const secondOf = (ms: number) => Math.floor(ms / 1000) * 1000;
const tripName = (idp: string) => `federation.${idp}`;

/** The IdPs opened once, for the round trip and `upstreams`. */
export const federationIdps = contract<ReadonlyMap<string, Idp>>("federation.idps");

/** Where a login lands when it named no return target: the operator's landing, or the public origin's root. */
const landingWith = (landing: string | undefined, at: Pick<Site, "origin">) =>
	landing ?? `${at.origin}/`;

export const landingTakes = [site] as const;

export const landingIn = async (c: BuildContext<Settings>) =>
	landingWith(c.section.landing, await c.get(site));

/** What `roundTripIn` and `landingIn` (`landingTakes`) take from the build context; the IdPs are the module's own. */
export const roundTripTakes = [
	roundTrips,
	upstreamContinuations,
	originEvidence,
	logins,
	...landingTakes,
] as const;

/** The round trip over the IdPs, ending in the continuation its start chose. */
export async function roundTripIn(
	c: BuildContext<Settings>,
	ends: Pick<Flow, "login">,
): Promise<(request: HttpRequest) => Promise<HttpResponse>> {
	const flow: Flow = {
		...ends,
		idps: await c.get(federationIdps),
		trips: await c.get(roundTrips),
		continuations: new Map(
			(await c.collect(upstreamContinuations)).map((continued) => [continued.name, continued]),
		),
		origin: await c.get(originEvidence),
		logins: await c.get(logins),
		clock: c.clock,
		log: c.log,
		landing: await landingIn(c),
		tripMs: c.section["transaction-lifetime"] * 1000,
	};
	return (request) => federated(flow, request);
}

/** Answers a start or a callback under the federation path; anything else there is not found. */
export async function federated(flow: Flow, request: HttpRequest): Promise<HttpResponse> {
	const [name = "", step, ...rest] = request.path.slice(base.length + 1).split("/");
	const idp = flow.idps.get(name);
	if (!idp || rest.length > 0 || (step !== undefined && step !== "callback")) {
		return jsonAnswer(404, { error: "not_found" });
	}
	const method = step !== undefined && idp.formPost ? "POST" : "GET";
	if (request.method !== method) {
		const refused = jsonAnswer(405, { error: "method_not_allowed" });
		return { ...refused, headers: { ...refused.headers, allow: method } };
	}
	const params = method === "POST" ? request.form : request.query;
	if (params.repeated().length > 0) {
		return jsonAnswer(400, { error: "repeated_parameter" });
	}
	const at: At = { name, idp, request, params };
	try {
		return step === undefined ? await start(flow, at) : await callback(flow, at);
	} catch (error) {
		if (isUnavailable(error)) return jsonAnswer(503, unavailable);
		throw error;
	}
}

interface At {
	readonly name: string;
	readonly idp: Idp;
	readonly request: HttpRequest;
	readonly params: Values;
}

/** What a start asks of the upstream's login, as its round trip carries it. */
const askedOf = (trip: Pick<TripCarried, "prompt" | "maxAgeSeconds">) => ({
	...(trip.prompt === undefined ? {} : { prompt: trip.prompt }),
	...(trip.maxAgeSeconds === undefined ? {} : { maxAgeSeconds: trip.maxAgeSeconds }),
});

async function start(flow: Flow, { name, idp, request, params }: At) {
	const field = (key: string) => params.single(key);
	const target = field("redirect_to");
	if (target !== undefined && !flow.logins.returnAllowed(target)) {
		return jsonAnswer(400, { error: "invalid_redirect" });
	}
	const maxAge = field("max_age");
	if (maxAge !== undefined && !/^[0-9]{1,9}$/.test(maxAge)) {
		return jsonAnswer(400, { error: "invalid_request" });
	}
	// The route's one word for a continuation: `link` (1 or true) chooses the one of that name.
	const named = ["1", "true"].includes(field("link") ?? "") ? "link" : undefined;
	const chosen = named === undefined ? undefined : flow.continuations.get(named);
	if (named !== undefined && !chosen) return missing(flow, name, named);
	const begun = await (chosen ?? flow.login).begin(request, name);
	if ("answer" in begun) return begun.answer;
	if (!flow.origin.sameOrigin(request)) {
		const live = await flow.trips.current(request, tripName(name));
		const kept = live && carriedOf(live.carried);
		if (live && kept) {
			const location = idp.upstream.authorizationUrl({
				state: live.state,
				nonce: live.nonce,
				challenge: live.challenge,
				challengeMethod: live.challengeMethod,
				redirectUri: idp.redirectUri,
				...askedOf(kept),
			});
			return sent(location, []);
		}
	}
	// What the browser asks of the upstream's login, kept for the callback to judge it by.
	const asked = askedOf({
		...(field("prompt") === "login" ? { prompt: "login" as const } : {}),
		...(maxAge === undefined ? {} : { maxAgeSeconds: Number(maxAge) }),
	});
	const trip = await flow.trips.begin({
		name: tripName(name),
		carried: toCarried({
			...(chosen ? { by: chosen.name } : {}),
			...(begun.kept === undefined ? {} : { kept: begun.kept }),
			...(target === undefined ? {} : { redirectTo: target }),
			...asked,
		}),
		lifetimeMs: flow.tripMs,
		crossSite: idp.formPost,
	});
	const location = idp.upstream.authorizationUrl({
		state: trip.state,
		nonce: trip.nonce,
		challenge: trip.challenge,
		challengeMethod: trip.challengeMethod,
		redirectUri: idp.redirectUri,
		...asked,
	});
	return sent(location, [trip.cookie]);
}

async function callback(flow: Flow, at: At) {
	const { name, request, params } = at;
	const taken = await flow.trips.take(request, tripName(name), params.single("state"));
	if (taken.kind === "none") return jsonAnswer(400, { error: "invalid_state" });
	const { cleared } = taken;
	const trip = tripOf(taken);
	if (!trip) return jsonAnswer(400, { error: "invalid_state" }, { cookies: cleared });
	try {
		return await finish(flow, at, trip, cleared);
	} catch (error) {
		if (isUnavailable(error)) return jsonAnswer(503, unavailable, { cookies: cleared });
		throw error;
	}
}

async function finish(flow: Flow, at: At, trip: Trip, cleared: readonly string[]) {
	const { name, idp, request, params } = at;
	const field = (key: string) => params.single(key);
	const from = determinedSource(request);
	const agent = request.headers.get("user-agent");
	const sender = {
		...(from === undefined ? {} : { source: from }),
		...(agent === undefined ? {} : { userAgent: agent }),
	};
	// A continuation's round trip never ends in a login, nor a login's in a continuation.
	const chosen = trip.by === undefined ? undefined : flow.continuations.get(trip.by);
	if (trip.by !== undefined && !chosen) return missing(flow, name, trip.by, cleared);
	// A round trip taken this far failed for the reason its answer names.
	const refused = (status: number, reason: string) => {
		if (chosen) chosen.failed({ idp: name, reason, kept: trip.kept, ...sender });
		else flow.login.failed({ name, reason, trip, ...sender });
		return jsonAnswer(status, { error: reason }, { cookies: cleared });
	};
	const code = field("code");
	if (field("error") !== undefined || code === undefined) return refused(400, "upstream_refused");
	const upstreamLogin = await exchanged(flow, at, trip, code);
	if (!upstreamLogin) return refused(502, "exchange_failed");
	if (!fresh(trip, upstreamLogin, idp.freshLoginAllowanceMs, flow.clock.now())) {
		return refused(401, "login_required");
	}
	if (chosen) {
		const lands = trip.redirectTo ?? flow.landing;
		return chosen.complete({
			request,
			idp: name,
			upstreamLogin,
			kept: trip.kept,
			lands,
			...sender,
			cleared,
		});
	}
	return flow.login.complete({ request, name, idp, upstreamLogin, trip, ...sender, cleared });
}

/** A continuation chosen that is not composed: refused, and warned, at the start or at the end. */
function missing(flow: Flow, idp: string, named: string, cleared: readonly string[] = []) {
	flow.log.warn("federation.continuation_missing", { idp, name: named });
	return jsonAnswer(400, { error: "continuation_unavailable" }, { cookies: cleared });
}

async function exchanged(flow: Flow, { name, idp, params }: At, trip: Trip, code: string) {
	try {
		return await idp.upstream.exchange({
			code,
			verifier: trip.verifier,
			redirectUri: idp.redirectUri,
			nonce: trip.nonce,
			iss: params.single("iss"),
		});
	} catch (error) {
		if (isUnavailable(error)) throw error;
		// Only the kind: an upstream's text and its tokens never reach logs or the browser.
		const kind = UpstreamRefused.is(error) ? "refused" : "failed";
		flow.log.warn("federation.exchange_failed", { idp: name, kind });
		return undefined;
	}
}

/** Whether the upstream login came after an ask to log in again, and within a max age; it must say when. */
function fresh(trip: Trip, upstreamLogin: UpstreamLogin, allowanceMs: number, now: number) {
	if (trip.prompt === undefined && trip.maxAgeSeconds === undefined) return true;
	const at = upstreamLogin.authenticatedAt;
	if (at === undefined) return false;
	if (trip.prompt === "login" && at + allowanceMs < secondOf(trip.startedAt)) return false;
	return trip.maxAgeSeconds === undefined || at + allowanceMs + trip.maxAgeSeconds * 1000 >= now;
}
