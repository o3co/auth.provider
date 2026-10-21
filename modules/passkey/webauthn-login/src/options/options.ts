import { type HttpRequest, jsonAnswer, type Route, use } from "@mod/http";
import type { BuildContext } from "@mod/kernel";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import { type Passkeys, passkeys } from "@mod/webauthn";
import type { Settings } from "../section.ts";

/** The client the options are for; false unless named as one non-empty string. */
function requesterOf({ fields, mistyped }: HttpRequest): string | false {
	if (mistyped?.has("client_id") || fields.repeated().includes("client_id")) return false;
	const id = fields.single("client_id");
	return id === undefined || id === "" ? false : id;
}

/** Request options the same for everyone, whose challenge only the client named redeems. */
/** The options route over the assembly's passkeys, limited per source as the package's section says. */
export const optionsRouteIn = async (c: BuildContext<Settings>) =>
	optionsRoute(await c.get(passkeys), { limit: c.section.requests, ms: c.section.window * 1000 });

export function optionsRoute(passkeys: Passkeys, window: Window): Route {
	return {
		method: "POST",
		path: "/oauth/webauthn/authentication/options",
		uses: [use(requestsPerSource, { name: "webauthn-login", window })],
		takes: ["json", "form", "none"],
		crossSite:
			"It reads no cookie and answers options the same for everyone, the challenge made for the client that asks.",
		handle: async (request) => {
			const requester = requesterOf(request);
			if (requester === false) {
				return jsonAnswer(400, { error: "invalid_request" });
			}
			return jsonAnswer(200, (await passkeys.challenge(requester)).options);
		},
	};
}
