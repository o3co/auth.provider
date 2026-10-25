import {
	type Back,
	type GrantIntents,
	type GrantsBrowser,
	grantIntents,
	type IntentRef,
} from "@mod/federation-grants";
import { type HttpRequest, type HttpResponse, jsonAnswer, noStore } from "@mod/http";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { determinedSource } from "@mod/request-source";
import { type Sessions, sessions } from "@mod/session";
import { type RoundTrips, roundTrips, type Taken } from "@mod/upstream-round-trip";
import {
	type DelegatedExchange,
	type Delegation,
	type DelegationStart,
	UpstreamRefused,
	type Upstreams,
	upstreams,
} from "@mod/upstreams";
import { name, type Settings } from "../section.ts";
import {
	type UpstreamAccounts,
	upstreamAccountOver,
	upstreamAccountTakes,
} from "../upstream-account/upstream-account.ts";

export interface ConnectParts {
	readonly sessions: Sessions;
	readonly upstreamAccount: UpstreamAccounts;
	readonly upstreams: Upstreams;
	readonly trips: RoundTrips;
	readonly intents: GrantIntents;
	readonly settings: Settings;
	readonly log: Log;
}

const plain = (status: number, text: string): HttpResponse => ({
	status,
	headers: {
		...noStore,
		"content-type": "text/plain; charset=utf-8",
		"referrer-policy": "no-referrer",
	},
	body: text,
});
const json = (status: number, body: unknown): HttpResponse =>
	jsonAnswer(status, body, { headers: { "referrer-policy": "no-referrer" } });
const see = (location: string): HttpResponse => ({
	status: 303,
	headers: { ...noStore, location, "referrer-policy": "no-referrer" },
});
const stale = () => plain(400, "This request has expired or has already been used. Start again.");
/** Each connection's round trip, by the name its cookie takes. */
const tripName = (connection: string) => `federation-grants.${connection}`;
const withCookies = (answer: HttpResponse, cookies: readonly string[]): HttpResponse => ({
	...answer,
	cookies: [...(answer.cookies ?? []), ...cookies],
});
const invalid = () =>
	json(400, { error: "invalid_request", error_description: "the request is not valid" });
/** Where the intents send the browser back, or the stale answer where they send it nowhere. */
const backTo = (back: Back) => (back.kind === "back" ? see(back.location) : stale());
/** The request's source, as the audit takes it. */
const sourceOf = (request: HttpRequest) => {
	const source = determinedSource(request);
	return source ? { source } : {};
};

/** A start as the upstream takes it: where to send the browser, refused as a value, or not askable now. */
const startOf = (delegation: Delegation | undefined, start: DelegationStart) => {
	try {
		const built = delegation?.authorizationUrl(start);
		if (built === undefined) return { kind: "unavailable" } as const;
		return typeof built === "string"
			? ({ kind: "url", location: built } as const)
			: ({ kind: "refused" } as const);
	} catch {
		// A start the type throws at cannot be asked now; never a 500.
		return { kind: "unavailable" } as const;
	}
};

/** The upstream's login for a code, or the error the browser is sent back with. */
const exchangedBy = async (delegation: Delegation, exchange: DelegatedExchange) => {
	try {
		return { kind: "login", login: await delegation.exchange(exchange) } as const;
	} catch (error) {
		if (isUnavailable(error)) return { kind: "failed", error: "temporarily_unavailable" } as const;
		if (UpstreamRefused.is(error)) return { kind: "failed", error: "upstream_error" } as const;
		throw error;
	}
};

/** The browser half: the link a client sends the user to, the question, the user's decision, and the upstream's callback. */
export function connectWith(p: ConnectParts): GrantsBrowser {
	const { intents, settings } = p;

	/** The session at use level, as the intent's subject; a short one is told whose it is first. */
	const entered = async (request: HttpRequest, subject: string) => {
		const other = { kind: "other" } as const;
		const entry = await p.sessions.enterFor(request, "use");
		if (entry.kind === "entered") return entry.session.context.subject === subject ? entry : other;
		if (entry.kind !== "short") return entry;
		// A short entry names no subject: the level that grants nothing tells whose session it is.
		const bare = await p.sessions.enterFor(request, "none");
		if (bare.kind !== "entered") return { kind: "unknown" } as const;
		const { context } = bare.session;
		return context.subject === subject ? { ...entry, context } : other;
	};

	const connect = async (request: HttpRequest): Promise<HttpResponse> => {
		const handle = request.query.single("request");
		const found = handle ? await intents.linked(handle) : undefined;
		if (!handle || found?.kind !== "linked") return stale();
		const { ref, view } = found;
		const self = intents.connectUrl(handle);
		const entry = await entered(request, view.subject);
		if (entry.kind === "absent") {
			const page = settings["login-page"];
			if (!page) return plain(401, "Sign in, then open this link again.");
			const login = new URL(page);
			login.searchParams.set("redirect_to", self);
			return see(login.href);
		}
		if (entry.kind === "other") return plain(403, "This request was made for another account.");
		if (entry.kind === "unknown") {
			intents.noted(ref, "reauthentication_required", sourceOf(request));
			return plain(403, "Sign in again to continue.");
		}
		// Told only to the subject's own session, so a link's holder learns nothing of the client.
		if (!(await intents.available(ref))) return plain(403, "This connection is not available.");
		if (entry.kind === "short") {
			const page = settings["step-up-page"];
			const { requirement, context } = entry;
			if (!page || !(await intents.steppedUp(ref, requirement, context.authenticatedAt))) {
				intents.noted(ref, "reauthentication_required", sourceOf(request));
				return plain(403, "Sign in again to continue.");
			}
			const raise = new URL(page);
			raise.searchParams.set("requirement", requirement);
			raise.searchParams.set("redirect_to", self);
			return see(raise.href);
		}
		// The first browser to take a question holds the intent; another is told to start again.
		const session = entry.session.id;
		if (view.session !== undefined && view.session !== session) return stale();
		const bound = await intents.bound(ref, session);
		if (bound.kind !== "bound") return stale();
		// Boot refuses connections without a page, and a grant whose connection is gone returned above.
		const page = new URL(settings.page ?? "");
		page.searchParams.set("challenge", bound.challenge);
		return see(page.href);
	};

	/** A question still open, asked of this browser's session for the intent's subject. */
	const asked = async (request: HttpRequest, challenge: string) => {
		const found = await intents.asked(challenge);
		if (found.kind !== "asked") return { kind: "refused", answer: invalid() } as const;
		const entry = await entered(request, found.view.subject);
		if (entry.kind === "absent") {
			return {
				kind: "refused",
				answer: json(401, {
					error: "login_required",
					error_description: "no authenticated session",
				}),
			} as const;
		}
		if (entry.kind !== "entered" || entry.session.id !== found.view.session) {
			return {
				kind: "refused",
				answer: json(403, {
					error: "reauthentication_required",
					error_description: "sign in again to continue",
				}),
			} as const;
		}
		if (!(await intents.permitted(found.ref))) {
			return {
				kind: "refused",
				answer: json(403, {
					error: "access_denied",
					error_description: "connection_not_permitted",
				}),
			} as const;
		}
		return found;
	};

	const question = async (request: HttpRequest): Promise<HttpResponse> => {
		const challenge = request.query.single("challenge");
		if (!challenge)
			return json(400, { error: "invalid_request", error_description: "challenge is required" });
		const read = await asked(request, challenge);
		if (read.kind === "refused") return read.answer;
		const { view } = read;
		return json(200, {
			challenge,
			client_id: view.client,
			connection: view.connection,
			scopes: view.scopes,
			...(view.resource ? { resource: view.resource } : {}),
			grant_expires_in: view.grantLifetimeMs / 1000,
			continues_after_logout: true,
			expires_in: Math.floor(view.expiresInMs / 1000),
		});
	};

	/** Ends the intent with why, audited, and sends the browser back with the error, if the client still lists the return. */
	const fail = async (
		request: HttpRequest,
		ref: IntentRef,
		error: string,
		outcome?: string,
	): Promise<HttpResponse> =>
		backTo(
			await intents.failed(ref, error, {
				...(outcome === undefined ? {} : { outcome }),
				...sourceOf(request),
			}),
		);

	const decide = async (request: HttpRequest): Promise<HttpResponse> => {
		const challenge = request.form.single("challenge");
		const decision = request.form.single("decision");
		if (!challenge)
			return json(400, { error: "invalid_request", error_description: "challenge is required" });
		if (decision !== "accept" && decision !== "deny") return invalid();
		const read = await asked(request, challenge);
		if (read.kind === "refused") return read.answer;
		const { ref } = read;
		if (decision === "deny") {
			const denied = await intents.denied(ref, challenge, sourceOf(request));
			return denied.kind === "invalid" ? invalid() : backTo(denied);
		}
		const start = intents.starting(ref);
		// Begun, and its start built, before the question is spent, so a start that cannot be asked
		// now leaves the question open; the round trip begun then is left to its lifetime.
		const trip = await p.trips.begin({
			name: tripName(read.view.connection),
			carried: start?.carried ?? {},
			lifetimeMs: start?.lifetimeMs ?? 1,
		});
		const started = startOf(start && p.upstreams.of(start.idp)?.delegation, {
			state: trip.state,
			nonce: trip.nonce,
			challenge: trip.challenge,
			challengeMethod: trip.challengeMethod,
			redirectUri: start?.redirectUri ?? intents.callbackUrl(read.view.connection),
			scopes: start?.scopes ?? read.view.scopes,
			...(start?.resource ? { resource: start.resource } : {}),
		});
		if (started.kind === "unavailable") {
			intents.noted(ref, "upstream_unavailable", sourceOf(request));
			return json(503, {
				error: "temporarily_unavailable",
				error_description: "upstream_unavailable",
			});
		}
		if (!(await intents.accepted(challenge))) return invalid();
		if (started.kind === "refused") {
			// The upstream will not start this delegation: the intent ends, and the client is told.
			return fail(request, ref, "grant_not_authorizable", "upstream_refused_start");
		}
		return withCookies(see(started.location), [trip.cookie]);
	};

	/** The checks a callback runs before it activates, each answering the error the browser is sent back with. */
	const verified = async (
		request: HttpRequest,
		ref: IntentRef,
		subject: string,
		session: string,
	) => {
		const entry = await entered(request, subject);
		if (entry.kind !== "entered" || entry.session.id !== session)
			return "reauthentication_required";
		return intents.stillValid(ref);
	};

	/** A taken round trip's callback, at the connection it was made for. */
	const callback = async (
		request: HttpRequest,
		name: string,
		taken: Extract<Taken, { kind: "taken" }>,
	): Promise<HttpResponse> => {
		const resumed = await intents.resumed(taken.carried);
		if (resumed.kind === "stale") return stale();
		if (resumed.kind === "unconfigured")
			return fail(request, resumed.ref, "grant_not_authorizable");
		const { ref, view } = resumed;
		const delegation = p.upstreams.of(view.idp)?.delegation;
		if (view.connection !== name || !delegation) {
			return fail(request, ref, "grant_not_authorizable");
		}
		const refused = await verified(request, ref, view.subject, view.session);
		if (refused) return fail(request, ref, refused);
		const code = request.query.single("code");
		if (request.query.repeated().length > 0 || request.query.has("error") || !code) {
			return fail(request, ref, request.query.has("error") ? "access_denied" : "upstream_error");
		}
		const exchanged = await exchangedBy(delegation, {
			code,
			verifier: taken.verifier,
			redirectUri: intents.callbackUrl(name),
			nonce: taken.nonce,
			iss: request.query.single("iss"),
			scopes: view.scopes,
			...(view.resource ? { resource: view.resource } : {}),
		});
		if (exchanged.kind === "failed") return fail(request, ref, exchanged.error);
		const { login } = exchanged;
		const upstream = { issuer: String(login.issuer), subject: String(login.subject) };
		const account = await p.upstreamAccount.refusal(
			{ subject: view.subject, upstream: view.expected.held },
			{ expectedUpstream: view.expected.subject },
			view.idp,
			upstream,
		);
		if (account) return fail(request, ref, account);
		const judged = intents.judged(ref, login.tokens);
		if (judged.kind === "refused") return fail(request, ref, judged.why);
		// Checked again just before the activation: the upstream leg may have taken long.
		const again = await verified(request, ref, view.subject, view.session);
		if (again) return fail(request, ref, again);
		return backTo(
			await intents.activated(ref, {
				upstream,
				tokens: judged.tokens,
				identityCheck: p.upstreamAccount.check,
				...sourceOf(request),
			}),
		);
	};

	/** Answers the browser half's routes; anything unavailable is a plain 503. */
	const guarded =
		(handle: (request: HttpRequest) => Promise<HttpResponse>) =>
		async (request: HttpRequest): Promise<HttpResponse> => {
			try {
				return await handle(request);
			} catch (error) {
				if (!isUnavailable(error)) throw error;
				p.log.error("federation-grants.browser_unavailable", { path: request.path.slice(0, 100) });
				// Audited as a failed connection, though which grant is not known here; best effort.
				try {
					intents.unanswered(sourceOf(request));
				} catch {}
				return plain(503, "This service is unavailable. Try again later.");
			}
		};
	return {
		connect: guarded(connect),
		question: guarded(question),
		decide: guarded(decide),
		callback: guarded(async (request) => {
			const name = intents.callbackOf(request.path);
			if (name === undefined) return plain(404, "Not found.");
			// Taken before any code is used, and only at the connection it was made for.
			const state = request.query.single("state");
			const taken = await p.trips.take(request, tripName(name), state);
			if (taken.kind === "none") return stale();
			// Spent from here on: its cookie goes with every answer, unavailable included.
			return withCookies(await guarded((r) => callback(r, name, taken))(request), taken.cleared);
		}),
	};
}

export const connectTakes = [
	grantIntents,
	sessions,
	upstreams,
	roundTrips,
	...upstreamAccountTakes,
] as const;

/** The browser half over the contracts the assembly gives; connections refuse boot without the page that asks the user. */
export const connectOver = async (c: BuildContext<Settings>) => {
	const intents = await c.get(grantIntents);
	if (intents.connected && !c.section.page)
		c.refuse(name, "connections need the page that asks the user");
	return connectWith({
		sessions: await c.get(sessions),
		upstreamAccount: await upstreamAccountOver(c, c.section["identity-check"]),
		upstreams: await c.get(upstreams),
		trips: await c.get(roundTrips),
		intents,
		settings: c.section,
		log: c.log,
	});
};
