import { createHash, randomBytes } from "node:crypto";
import type { Browser, Landing } from "./browser.ts";
import { idpName, probe } from "./scene.ts";

/** How a federation login through the suite ended, as the app answered its callback. */
export interface SignIn {
	/** The app's answer to the callback: what the browser stopped at. */
	readonly callback: Landing;
	/** The app sent the browser on to the return target, as a login it took. */
	readonly returned: boolean;
}

/**
 * Starts a federation login at the app on `origin`, returning to `returnTarget`, and goes through
 * the suite's OP and back, stopping at the app's answer to its callback: a redirect to the return
 * target is never followed.
 */
export async function signIn(
	b: Browser,
	given: { readonly origin: string; readonly returnTarget: string; readonly signal?: AbortSignal },
): Promise<SignIn> {
	const start = new URL(`/session/oauth/federation/${idpName}`, given.origin);
	start.searchParams.set("redirect_to", given.returnTarget);
	const target = new URL(given.returnTarget);
	const callback = await b.visit(start.href, {
		follow: (url) => !(url.origin === target.origin && url.pathname === target.pathname),
		...(given.signal ? { signal: given.signal } : {}),
	});
	const location = callback.hops.at(-1)?.location;
	return {
		callback,
		returned: callback.status === 302 && location !== undefined && location === target.href,
	};
}

/**
 * The local subject the browser is logged in as at the app on `origin`, asked by a silent
 * authorization request of the probe client and its code's id_token; none where it is not.
 */
export async function loggedInAs(
	b: Browser,
	given: { readonly origin: string; readonly signal?: AbortSignal },
): Promise<string | undefined> {
	const verifier = randomBytes(32).toString("base64url");
	const asked = new URLSearchParams({
		response_type: "code",
		client_id: probe.id,
		redirect_uri: probe.redirectUri,
		scope: "openid",
		state: "probe",
		prompt: "none",
		code_challenge: createHash("sha256").update(verifier).digest("base64url"),
		code_challenge_method: "S256",
	});
	const signal = given.signal ? { signal: given.signal } : {};
	const answered = await b.visit(`${given.origin}/oauth/authorize?${asked}`, {
		follow: () => false,
		...signal,
	});
	const location = answered.hops.at(-1)?.location;
	if (answered.status !== 302 || !location?.startsWith(`${probe.redirectUri}?`)) {
		throw new Error(`the probe's silent request was answered ${answered.status}, not sent back`);
	}
	const back = new URL(location).searchParams;
	if (back.get("error") === "login_required") return undefined;
	const code = back.get("code");
	if (code === null)
		throw new Error(`the probe's silent request was refused: ${back.get("error")}`);
	const token = await b.visit(
		`${given.origin}/oauth/token`,
		{ follow: () => false, ...signal },
		new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: probe.redirectUri,
			code_verifier: verifier,
			client_id: probe.id,
			client_secret: probe.secret,
		}).toString(),
	);
	if (token.status !== 200) throw new Error(`the probe's code was refused: ${token.status}`);
	const idToken = String((JSON.parse(token.body) as Record<string, unknown>).id_token ?? "");
	const claims = JSON.parse(Buffer.from(idToken.split(".")[1] ?? "", "base64url").toString());
	if (typeof claims.sub !== "string" || claims.sub === "") {
		throw new Error("the probe's id_token names no subject");
	}
	return claims.sub;
}
