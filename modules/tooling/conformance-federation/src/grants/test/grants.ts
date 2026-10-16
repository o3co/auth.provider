import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { type Browser, browser as openBrowser } from "../../../test/browser.ts";
import { type Authorized, fakeUpstream } from "../../../test/upstream.ts";
import { federationScene, type GrantsPart } from "../../main.ts";

export const origin = "https://issuer.example";
const landing = "https://app.example/home";
export const page = `${origin}/grant-consent`;
export const back = "https://worker.example/connected";
export const scopes = ["openid", "offline_access", "calendar.read"];
const upstreamClient = { id: "as-client", secret: "as-client-secret-0123456789" };
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
const pair = generateKeyPairSync("ed25519");

/** A backend that holds grants for the connection `calendar`. */
const worker = (id: string): ClientScene => ({
	id,
	kind: "confidential",
	method: "client_secret_basic",
	secret: secretOf(id),
	grants: ["client_credentials"],
	scopes: ["read"],
	federationGrants: { connections: ["calendar"], returnUris: [back] },
});

let sender = 0;

/**
 * A deployment with federation grants for the connection `calendar` at a fake upstream, two
 * backends (`worker`, `other-worker`) and two users who log in through that upstream.
 */
export async function grantsTarget(more: Partial<GrantsPart> = {}) {
	const corp = await fakeUpstream(upstreamClient);
	const scene = federationScene({
		origin,
		keys: {
			signing: {
				kid: "fed",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		idps: [
			{
				name: "corp",
				issuer: corp.issuer,
				clientId: upstreamClient.id,
				clientSecret: upstreamClient.secret,
			},
		],
		landing,
		returnTargets: [],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-alice" },
			},
			{
				identifier: "bob",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-bob" },
			},
		],
		clients: [worker("worker"), worker("other-worker")],
		grants: {
			page,
			connections: [{ name: "calendar", idp: "corp", scopes, maxAccessTokenSeconds: 3600 }],
			...more,
		},
	});
	const running: Started = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	const base = running.baseUrl;

	/** A client's call, by HTTP Basic with a JSON body, each from an address of its own. */
	const call = async (path: string, json: Record<string, unknown>, as = "worker") => {
		const res = await fetch(`${base}${path}`, {
			method: "POST",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": `203.0.113.${(++sender % 250) + 1}`,
				"content-type": "application/json",
				authorization: `Basic ${Buffer.from(`${as}:${secretOf(as)}`).toString("base64")}`,
			},
			body: JSON.stringify(json),
		});
		const text = await res.text();
		return {
			status: res.status,
			text,
			retryAfter: res.headers.get("retry-after"),
			body: (text.startsWith("{") ? JSON.parse(text) : {}) as Record<string, unknown>,
		};
	};
	const lodge = (fields: Record<string, unknown> = {}, as = "worker") =>
		call(
			"/oauth/federation-grants",
			{ connection: "calendar", sub: "alice", redirect_uri: back, state: "st-1", ...fields },
			as,
		);
	const grantCall = (
		id: string,
		step: string,
		fields: Record<string, unknown> = {},
		as = "worker",
	) => call(`/oauth/federation-grants/${id}/${step}`, { sub: "alice", ...fields }, as);

	/** A browser logged in through the upstream as the user its upstream subject names. */
	const loggedIn = async (subject = "u-alice"): Promise<Browser> => {
		const b = openBrowser(() => base, origin);
		const started = await b.get("/session/oauth/federation/corp");
		const done = await b.get(
			`/session/oauth/federation/corp/callback?${corp.authorize(started.location, { subject })}`,
		);
		if (done.location !== landing) throw new Error(`not logged in: ${done.status}`);
		return b;
	};
	/** Opens a connect link in the browser; answers the challenge the page was sent. */
	const open = async (b: Browser, connectUri: unknown) => {
		const at = new URL(String(connectUri));
		const opened = await b.get(`${at.pathname}${at.search}`);
		return {
			opened,
			challenge: new URL(opened.location || page, origin).searchParams.get("challenge") ?? "",
		};
	};
	/** The page's answer, posted as a form from the browser, from the provider's origin unless told. */
	const answer = async (
		b: Browser,
		form: Record<string, string>,
		headers: Record<string, string> = { origin },
	) => {
		const res = await fetch(`${base}/session/federation-grants/consent`, {
			method: "POST",
			redirect: "manual",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": b.from,
				"x-forwarded-host": new URL(origin).host,
				"content-type": "application/x-www-form-urlencoded",
				cookie: b.cookies(),
				...headers,
			},
			body: new URLSearchParams(form),
		});
		return { status: res.status, location: res.headers.get("location") ?? "" };
	};
	const callback = (b: Browser, query: URLSearchParams) =>
		b.get(`/session/federation-grants/callback/calendar?${query}`);

	/**
	 * Lodges (or renews) an intent and walks a logged-in browser through the link, the question and
	 * the upstream, which hands over `tokens`; answers the callback.
	 */
	const connected = async (
		tokens: Authorized["tokens"] = {},
		at: { readonly renew?: string; readonly b?: Browser } = {},
	) => {
		const lodged = at.renew
			? await grantCall(at.renew, "reauthorize", { redirect_uri: back, state: "st-1" })
			: await lodge();
		const b = at.b ?? (await loggedIn());
		const { challenge } = await open(b, lodged.body.connect_uri);
		const accepted = await answer(b, { challenge, decision: "accept" });
		const query = corp.authorize(accepted.location, {
			subject: "u-alice",
			tokens: { scope: scopes.join(" "), ...tokens },
		});
		const done = await callback(b, query);
		return { id: String(lodged.body.grant_id), lodged, done, b };
	};
	/** Where a callback sent the browser back to, as its query. */
	const returned = (done: { location: string }) => new URL(done.location).searchParams;

	return {
		corp,
		call,
		lodge,
		grantCall,
		loggedIn,
		open,
		answer,
		callback,
		connected,
		returned,
		stop: async () => {
			await running.stop();
			await corp.stop();
		},
	};
}

export type GrantsTarget = Awaited<ReturnType<typeof grantsTarget>>;
