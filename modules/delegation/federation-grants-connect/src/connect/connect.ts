import { type GrantIntents, type GrantsBrowser, grantIntents } from "@mod/federation-grants";
import type { HttpRequest, HttpResponse } from "@mod/http";
import { type BuildContext, isUnavailable, type Log } from "@mod/kernel";
import { type Sessions, sessions } from "@mod/session";
import { type RoundTrips, roundTrips } from "@mod/upstream-round-trip";
import { type Upstreams, upstreams } from "@mod/upstreams";
import { name, type Settings } from "../section.ts";
import {
	type UpstreamAccounts,
	upstreamAccountOver,
	upstreamAccountTakes,
} from "../upstream-account/upstream-account.ts";
import { callbackWith } from "./callback.ts";
import { connectCommonWith, plain, sourceOf, stale, tripName, withCookies } from "./common.ts";
import { connectingWith } from "./connecting.ts";
import { decidingWith } from "./deciding.ts";

export interface ConnectParts {
	readonly sessions: Sessions;
	readonly upstreamAccount: UpstreamAccounts;
	readonly upstreams: Upstreams;
	readonly trips: RoundTrips;
	readonly intents: GrantIntents;
	readonly settings: Settings;
	readonly log: Log;
}

/** The most characters of a path an outage's log line carries. */
const pathLogMax = 100;

export function connectWith(p: ConnectParts): GrantsBrowser {
	const common = connectCommonWith(p);
	const { intents } = common;
	const { connect } = connectingWith(common);
	const { question, decide } = decidingWith(common);
	const { callback } = callbackWith(common);

	/** Answers the browser half's routes; anything unavailable is a plain 503. */
	const guarded =
		(handle: (request: HttpRequest) => Promise<HttpResponse>) =>
		async (request: HttpRequest): Promise<HttpResponse> => {
			try {
				return await handle(request);
			} catch (error) {
				if (!isUnavailable(error)) throw error;
				p.log.error("federation-grants.browser_unavailable", {
					path: request.path.slice(0, pathLogMax),
				});
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
	// The operator's choice, yet said at every start: another user's upstream account is taken.
	if (c.section["identity-check"] === "none") {
		c.log.warn("federation-grants-connect.identity_unchecked", {
			reason: "a callback whose upstream account another user holds is not refused",
		});
	}
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
