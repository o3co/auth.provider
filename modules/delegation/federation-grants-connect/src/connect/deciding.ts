import type { HttpRequest, HttpResponse } from "@mod/http";

import {
	backTo,
	type ConnectCommon,
	invalid,
	json,
	see,
	sourceOf,
	startOf,
	tripName,
	withCookies,
} from "./common.ts";

/** The question shown, and the decision on it. */
export function decidingWith({ p, intents, asked, fail }: ConnectCommon) {
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
	return { question, decide };
}
