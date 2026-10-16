import { type HttpRequest, noStore, type Route, use } from "@mod/http";
import { requestsPerSource, type Window } from "@mod/rate-limit";
import type { Passkeys } from "@mod/webauthn";

/** The client the options are for; false unless named as one non-empty string. */
function requesterOf({ fields, mistyped }: HttpRequest): string | false {
	if (mistyped?.has("client_id") || fields.repeated().includes("client_id")) return false;
	const id = fields.single("client_id");
	return id === undefined || id === "" ? false : id;
}

/** Request options the same for everyone, whose challenge only the client named redeems. */
export function optionsRoute(passkeys: Passkeys, window: Window): Route {
	return {
		method: "POST",
		path: "/oauth/webauthn/authentication/options",
		uses: [use(requestsPerSource, { name: "webauthn-login", window })],
		takes: ["json", "form", "none"],
		handle: async (request) => {
			const requester = requesterOf(request);
			if (requester === false) {
				return { status: 400, headers: noStore, body: { json: { error: "invalid_request" } } };
			}
			return {
				status: 200,
				headers: noStore,
				body: { json: (await passkeys.challenge(requester)).options },
			};
		},
	};
}
