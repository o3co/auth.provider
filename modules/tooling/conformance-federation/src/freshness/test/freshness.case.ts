import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Browser, browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { type Authorized, fakeUpstream } from "../../../test/upstream.ts";
import { federationScene } from "../../main.ts";

const origin = "https://issuer.example";
const start = "/session/oauth/federation/corp";
const pair = generateKeyPairSync("ed25519");
const client = { id: "as-client", secret: "as-client-secret-0123456789" };
const verifier = "v".repeat(43);

let upstream: Awaited<ReturnType<typeof fakeUpstream>>;
let running: Started;
let base = "";
beforeAll(async () => {
	upstream = await fakeUpstream(client);
	const scene = federationScene({
		origin,
		keys: {
			signing: {
				kid: "fresh",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		idps: [
			{ name: "corp", issuer: upstream.issuer, clientId: client.id, clientSecret: client.secret },
		],
		landing: "https://app.example/home",
		returnTargets: [],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "corp", subject: "u-alice" },
			},
		],
		clients: [probeClient],
	});
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await upstream?.stop();
});

const browser = () => openBrowser(() => base, origin);
const seconds = () => Math.floor(Date.now() / 1000);

/** Logs the browser in through the upstream, which says what `as` says, returning where `redirectTo` names. */
async function federated(
	b: Browser,
	as: Authorized,
	redirectTo?: string,
	more: Record<string, string> = {},
) {
	const asked = { ...(redirectTo === undefined ? {} : { redirect_to: redirectTo }), ...more };
	const query = Object.keys(asked).length === 0 ? "" : `?${new URLSearchParams(asked)}`;
	const started = await b.get(`${start}${query}`);
	expect(started.status).toBe(302);
	const back = await b.get(`${start}/callback?${upstream.authorize(started.location, as)}`);
	return Object.assign(back, { asked: new URL(started.location).searchParams });
}

/** An authorization request from the probe client, with what a scene adds. */
const authorize = (b: Browser, extra: Record<string, string>) =>
	b.get(
		`/oauth/authorize?${new URLSearchParams({
			response_type: "code",
			client_id: probeClient.id,
			redirect_uri: "https://app.example/cb",
			scope: "openid",
			state: "s1",
			code_challenge: createHash("sha256").update(verifier).digest("base64url"),
			code_challenge_method: "S256",
			...extra,
		})}`,
	);

/** Where the deployment sent the browser to log in again, and the request it returns to. */
function sentToLogIn(location: string) {
	// A relative location is the deployment's own page.
	const login = new URL(location, origin);
	expect(`${login.origin}${login.pathname}`).toBe(`${origin}/login`);
	return String(login.searchParams.get("redirect_to"));
}

/** What the login page hands to a login it starts at an upstream: the `prompt` and `max_age` it was told. */
function handedOn(location: string) {
	const login = new URL(location, origin);
	return Object.fromEntries(
		["prompt", "max_age"].flatMap((name) => {
			const value = login.searchParams.get(name);
			return value === null ? [] : [[name, value]];
		}),
	);
}

// The legacy build returns from a federation login only to a listed target, never to an authorization request.
describe.skipIf(areaTarget().differs("federation-returns-to-authorization"))(
	"federation logins meeting a client's demand for a fresh login",
	() => {
		it("meets prompt=login only with a login the upstream says came after the demand, never one it says is older [oidc-core-3.1.2.3-b] [oidc-core-3.1.2.1-l] [oidc-core-3.1.2.1-m]", async () => {
			const b = browser();
			const hourAgo = { subject: "u-alice", authTime: seconds() - 3600 };
			expect((await federated(b, hourAgo)).status).toBe(302);
			const back = sentToLogIn((await authorize(b, { prompt: "login" })).location);
			// The upstream still holds its own session, and says the user logged in an hour ago.
			const again = await federated(b, hourAgo, back);
			expect(again.location).toBe(back);
			// Back with a login no newer, the request is refused, never sent round again.
			const stale = new URL((await b.get(back.slice(origin.length))).location);
			expect([stale.searchParams.get("error"), stale.searchParams.has("code")]).toEqual([
				"login_required",
				false,
			]);
			// Logging in at the upstream now meets it.
			const fresh = sentToLogIn((await authorize(b, { prompt: "login" })).location);
			await federated(b, { subject: "u-alice", authTime: seconds() + 1 }, fresh);
			const answered = await b.get(fresh.slice(origin.length));
			expect(new URL(answered.location).searchParams.has("code")).toBe(true);
		});

		it("meets prompt=login in one trip through an upstream whose clock is a little behind, within its allowance", async () => {
			const b = browser();
			expect((await federated(b, { subject: "u-alice", authTime: seconds() - 3600 })).status).toBe(
				302,
			);
			const sent = (await authorize(b, { prompt: "login" })).location;
			const back = sentToLogIn(sent);
			// The login page hands on what it was told; the upstream's clock says ten seconds before our start.
			const again = await federated(
				b,
				{ subject: "u-alice", authTime: seconds() - 10 },
				back,
				handedOn(sent),
			);
			expect(again.location).toBe(back);
			const answered = await b.get(back.slice(origin.length));
			expect(new URL(answered.location).searchParams.has("code")).toBe(true);
		});

		it("tells the login page the prompt=login and max_age asked, which reach the upstream through it [oidc-core-3.1.3.7-n]", async () => {
			const b = browser();
			const sent = (await authorize(b, { prompt: "login", max_age: "600" })).location;
			expect(handedOn(sent)).toEqual({ prompt: "login", max_age: "600" });
			const back = sentToLogIn(sent);
			const again = await federated(
				b,
				{ subject: "u-alice", authTime: seconds() },
				back,
				handedOn(sent),
			);
			expect(again.asked.get("prompt")?.split(" ")).toContain("login");
			expect(again.asked.get("max_age")).toBe("600");
			const answered = await b.get(back.slice(origin.length));
			expect(new URL(answered.location).searchParams.has("code")).toBe(true);
		});

		it("meets a max age only with a login the upstream says when it made [oidc-core-3.1.3.7-n]", async () => {
			const b = browser();
			const back = sentToLogIn((await authorize(b, { max_age: "600" })).location);
			const silent = await federated(b, { subject: "u-alice" }, back);
			expect(silent.location).toBe(back);
			// Still unknown after the login it sent for: the client is told to log the user in, with no code.
			const refused = new URL((await b.get(back.slice(origin.length))).location);
			expect([refused.searchParams.get("error"), refused.searchParams.has("code")]).toEqual([
				"login_required",
				false,
			]);
			const again = sentToLogIn((await authorize(b, { max_age: "600" })).location);
			const said = await federated(b, { subject: "u-alice", authTime: seconds() }, again);
			expect(said.location).toBe(again);
			const answered = await b.get(again.slice(origin.length));
			expect(new URL(answered.location).searchParams.has("code")).toBe(true);
		});
	},
);

/** The claims of the ID token a code the deployment just gave the browser redeems for. */
async function idTokenClaims(b: Browser) {
	const answered = await authorize(b, {});
	const code = new URL(answered.location, origin).searchParams.get("code") ?? "";
	const token = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: {
			"x-forwarded-proto": "https",
			"x-forwarded-for": b.from,
			"x-forwarded-host": new URL(origin).host,
			"content-type": "application/x-www-form-urlencoded",
		},
		body: new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: "https://app.example/cb",
			code_verifier: verifier,
			client_id: probeClient.id,
			client_secret: probeClient.secret ?? "",
		}),
	});
	const idToken = String(((await token.json()) as Record<string, unknown>).id_token ?? "");
	return JSON.parse(Buffer.from(idToken.split(".")[1] ?? "", "base64url").toString());
}

// The legacy build puts the time of its own callback in the ID token, whatever the upstream said.
describe.skipIf(areaTarget().differs("federation-auth-time-from-upstream"))(
	"the ID token after a federation login",
	() => {
		it("says when the user logged in only as the upstream says it, and nothing where the upstream says nothing [oidc-core-15.1-e]", async () => {
			const said = browser();
			const at = seconds() - 60;
			expect((await federated(said, { subject: "u-alice", authTime: at })).status).toBe(302);
			expect((await idTokenClaims(said)).auth_time).toBe(at);
			const silent = browser();
			expect((await federated(silent, { subject: "u-alice" })).status).toBe(302);
			expect(await idTokenClaims(silent)).not.toHaveProperty("auth_time");
		});
	},
);
