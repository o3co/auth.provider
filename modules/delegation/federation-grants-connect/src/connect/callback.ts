import type { IntentRef } from "@mod/federation-grants";
import type { HttpRequest, HttpResponse } from "@mod/http";
import type { Taken } from "@mod/upstream-round-trip";

import { backTo, type ConnectCommon, exchangedBy, sourceOf, stale } from "./common.ts";

/** A taken round trip's callback: the upstream's answer checked, then the grant activated. */
export function callbackWith({ p, intents, entered, fail }: ConnectCommon) {
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
	return { callback };
}
