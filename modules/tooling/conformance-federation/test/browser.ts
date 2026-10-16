import { createHash } from "node:crypto";
import type { ClientScene } from "@mod/conformance-oauth";

/** The client a scene asks with, silently, whether a browser is logged in. */
export const probeClient: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code"],
	scopes: ["openid", "read"],
	defaultScopes: ["read"],
	redirectUris: ["https://app.example/cb"],
	firstParty: true,
};
const callback = "https://app.example/cb";
const verifier = "v".repeat(43);

let sender = 0;
/** A browser of its own, with its own cookies and its own address (`from`), at a deployment's origin. */
export function browser(base: () => string, origin: string) {
	const from = `198.51.100.${++sender}`;
	const jar = new Map<string, string>();
	/** The cookies the browser holds now, as it would send them. */
	const cookies = () => [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
	/**
	 * Sends with the browser's cookies, or with cookies it held before where a scene keeps them; a
	 * form is posted with the headers of the page that posts it.
	 */
	const send = async (
		path: string,
		kept?: string,
		posted?: { readonly form: URLSearchParams; readonly headers: Record<string, string> },
		extra: Record<string, string> = {},
	) => {
		const res = await fetch(`${base()}${path}`, {
			redirect: "manual",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": from,
				"x-forwarded-host": new URL(origin).host,
				cookie: kept ?? cookies(),
				...extra,
				...(posted
					? { "content-type": "application/x-www-form-urlencoded", ...posted.headers }
					: {}),
			},
			...(posted ? { method: "POST", body: posted.form.toString() } : {}),
		});
		const set: string[] = [];
		for (const line of res.headers.getSetCookie()) {
			const [pairText = ""] = line.split(";");
			const at = pairText.indexOf("=");
			const [name, value] = [pairText.slice(0, at), pairText.slice(at + 1)];
			if (value === "" || /max-age=0/i.test(line) || /expires=thu, 01 jan 1970/i.test(line))
				jar.delete(name);
			else {
				jar.set(name, value);
				set.push(name);
			}
		}
		const text = await res.text();
		return {
			status: res.status,
			location: res.headers.get("location") ?? "",
			headers: res.headers,
			set,
			text,
			body: text.startsWith("{") ? (JSON.parse(text) as Record<string, unknown>) : undefined,
		};
	};
	const get = (path: string, kept?: string) => send(path, kept);
	const navigate = (path: string, headers: Record<string, string>) =>
		send(path, undefined, undefined, headers);
	/** Posts a form from another site's page, as an upstream answering in a posted form has it sent. */
	const post = (path: string, form: URLSearchParams, at: string, kept?: string) =>
		send(path, kept, { form, headers: { origin: at, "sec-fetch-site": "cross-site" } });
	let csrf = "";
	/** Posts a form as the deployment's own page does: same origin, with the double-submit token. */
	const submit = async (path: string, form: Record<string, string>) => {
		csrf ||= String((await get("/session/csrf")).body?.csrf_token);
		return send(path, undefined, {
			form: new URLSearchParams(form),
			headers: { origin, "x-csrf-token": csrf },
		});
	};
	/** Whether the browser is logged in: a silent authorization request gets a code. */
	const session = async () => {
		const asked = new URLSearchParams({
			response_type: "code",
			client_id: probeClient.id,
			redirect_uri: callback,
			scope: "openid",
			state: "probe",
			prompt: "none",
			code_challenge: createHash("sha256").update(verifier).digest("base64url"),
			code_challenge_method: "S256",
		});
		const res = await get(`/oauth/authorize?${asked}`);
		if (!res.location.startsWith(`${callback}?`))
			throw new Error(`not a probe answer: ${res.status}`);
		return new URL(res.location).searchParams.has("code");
	};
	const loggedInAs = async () => {
		const asked = new URLSearchParams({
			response_type: "code",
			client_id: probeClient.id,
			redirect_uri: callback,
			scope: "openid",
			state: "probe",
			prompt: "none",
			code_challenge: createHash("sha256").update(verifier).digest("base64url"),
			code_challenge_method: "S256",
		});
		const res = await get(`/oauth/authorize?${asked}`);
		const code = new URL(res.location || callback).searchParams.get("code");
		if (!code) return undefined;
		const token = await fetch(`${base()}/oauth/token`, {
			method: "POST",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": from,
				"x-forwarded-host": new URL(origin).host,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: callback,
				code_verifier: verifier,
				client_id: probeClient.id,
				client_secret: probeClient.secret ?? "",
			}),
		});
		const idToken = String(((await token.json()) as Record<string, unknown>).id_token ?? "");
		const claims = JSON.parse(Buffer.from(idToken.split(".")[1] ?? "", "base64url").toString());
		return String(claims.sub);
	};
	return { from, get, navigate, post, submit, cookies, session, loggedInAs };
}

export type Browser = ReturnType<typeof browser>;
