import type { HttpRequest, HttpResponse } from "@mod/http";

import { type ConnectCommon, plain, see, sourceOf, stale } from "./common.ts";

/** The browser sent to connect: the link checked, the session entered, and the question asked or the round trip begun. */
export function connectingWith({ intents, settings, entered }: ConnectCommon) {
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
	return { connect };
}
