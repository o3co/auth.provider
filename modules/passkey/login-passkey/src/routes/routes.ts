import { type Cookies, cookies } from "@mod/cookies";
import { csrfChecked } from "@mod/csrf";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route, use } from "@mod/http";
import { type BuildContext, isUnavailable } from "@mod/kernel";
import { type Logins, logins } from "@mod/login-gates";
import { type Passkeys, passkeys } from "@mod/passkeys";
import { attemptsPerSource, type Window } from "@mod/rate-limit";
import { ceremonies } from "@mod/webauthn";
import { type Recorded, recordedIn } from "../audited/audited.ts";
import { type Opening, openingIn } from "../opening/opening.ts";
import type { Settings } from "../section.ts";

export interface RouteParts {
	readonly passkeys: Passkeys;
	readonly cookies: Cookies;
	readonly logins: Pick<Logins, "returnAllowed">;
	readonly open: Opening;
	readonly recorded: Recorded;
	/** `n` random bytes. */
	readonly random: (n: number) => Uint8Array;
	/** How long a challenge can be answered, in ms: the requester's cookie lives as long. */
	readonly lifetimeMs: number;
	readonly window: Window;
}

/** The cookie that ties an assertion to the browser that asked its options. */
const requesterCookie = "passkey-login";

/** The options route, then the login route that redeems what the options' challenge was answered with. */
export function loginRoutes(p: RouteParts): Route[] {
	const options = async (): Promise<HttpResponse> => {
		const requester = Buffer.from(p.random(32)).toString("base64url");
		const { options } = await p.passkeys.challenge(requester);
		const cookie = p.cookies.write(requesterCookie, requester, Math.ceil(p.lifetimeMs / 1000));
		return jsonAnswer(200, options, { cookies: [cookie] });
	};
	const login = async (request: HttpRequest): Promise<HttpResponse> => {
		if (request.fields.repeated().length > 0) {
			return jsonAnswer(400, { error: "repeated_parameter" });
		}
		const destination = request.fields.single("redirect_to");
		// A JSON destination that is not a string is refused; null is none.
		const mistyped = request.mistyped?.has("redirect_to") && request.json?.redirect_to !== null;
		if (mistyped || (destination !== undefined && !p.logins.returnAllowed(destination))) {
			return jsonAnswer(400, { error: "invalid_redirect" });
		}
		const response = request.json?.response;
		if (typeof response !== "object" || response === null || Array.isArray(response)) {
			return jsonAnswer(400, { error: "invalid_request" });
		}
		const refuse = (reason: string) => {
			p.recorded.session(request, "refused", undefined, reason);
			return jsonAnswer(401, { error: "passkey_login_failed" });
		};
		const found = p.cookies.lookup(request, requesterCookie);
		if (found.kind !== "found") return refuse("challenge");
		const asserted = await p.passkeys.assert(response, found.value);
		if (asserted.kind === "refused") return refuse(asserted.reason);
		const done = destination === undefined ? {} : { redirect_to: destination };
		return p.open(request, asserted, done);
	};
	const answered =
		(handle: (request: HttpRequest) => Promise<HttpResponse>) => async (request: HttpRequest) => {
			try {
				return await handle(request);
			} catch (error) {
				if (isUnavailable(error)) return jsonAnswer(503, { error: "temporarily_unavailable" });
				throw error;
			}
		};
	return [
		{
			method: "POST",
			path: "/session/login/passkey/options",
			takes: ["json", "form", "none"],
			// The count comes after the CSRF check, before the handler judges the request.
			uses: [
				use(csrfChecked),
				use(attemptsPerSource, { name: "login-passkey.options", window: p.window }),
			],
			handle: answered(options),
		},
		{
			method: "POST",
			path: "/session/login/passkey",
			takes: ["json"],
			uses: [use(csrfChecked), use(attemptsPerSource, { name: "login-passkey", window: p.window })],
			handle: async (request) => {
				const response = await answered(login)(request);
				// The challenge is redeemed once: every login answer, whatever it is, ends its requester's cookie.
				const ended = p.cookies.write(requesterCookie, "", 0);
				return { ...response, cookies: [...(response.cookies ?? []), ended] };
			},
		},
	];
}

export const routesIn = async (c: BuildContext<Settings>) =>
	loginRoutes({
		passkeys: await c.get(passkeys),
		cookies: await c.get(cookies),
		logins: await c.get(logins),
		open: await openingIn(c),
		recorded: await recordedIn(c),
		random: c.random.bytes,
		lifetimeMs: (await c.get(ceremonies)).lifetimeMs,
		window: { limit: c.section.attempts, ms: c.section.window * 1000 },
	});
